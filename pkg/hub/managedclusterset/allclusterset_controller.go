package managedclusterset

import (
	"context"
	"fmt"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	clientset "open-cluster-management.io/api/client/cluster/clientset/versioned"
	clusterinformerv1 "open-cluster-management.io/api/client/cluster/informers/externalversions/cluster/v1"
	clusterinformerv1beta1 "open-cluster-management.io/api/client/cluster/informers/externalversions/cluster/v1beta1"
	clusterlisterv1 "open-cluster-management.io/api/client/cluster/listers/cluster/v1"
	clusterlisterv1beta1 "open-cluster-management.io/api/client/cluster/listers/cluster/v1beta1"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
)

const (
	defaultClusterSetName = "default"
)

// defaultManagedClusterSetController creates the default clusterset if it does not exists, and move
// managed clusters that belongs no clusterset to the default clusterset.
type defaultManagedClusterSetController struct {
	clusterClient    clientset.Interface
	clusterLister    clusterlisterv1.ManagedClusterLister
	clusterSetLister clusterlisterv1beta1.ManagedClusterSetLister
	eventRecorder    events.Recorder
}

// NewDefaultManagedClusterSetController creates a new default managed cluster set controller
func NewDefaultManagedClusterSetController(
	clusterClient clientset.Interface,
	clusterInformer clusterinformerv1.ManagedClusterInformer,
	clusterSetInformer clusterinformerv1beta1.ManagedClusterSetInformer,
	recorder events.Recorder) factory.Controller {
	c := &defaultManagedClusterSetController{
		clusterClient:    clusterClient,
		clusterLister:    clusterInformer.Lister(),
		clusterSetLister: clusterSetInformer.Lister(),
		eventRecorder:    recorder.WithComponentSuffix("default-cluster-set-controller"),
	}

	return factory.New().
		WithFilteredEventsInformersQueueKeyFunc(func(obj runtime.Object) string {
			// return empty if there is any change on the default clusterset
			return ""
		}, func(obj interface{}) bool {
			accessor, err := meta.Accessor(obj)
			if err != nil {
				return false
			}
			// only enqueue the default clusterset
			if accessor.GetName() == defaultClusterSetName {
				return true
			}
			return false
		}, clusterSetInformer.Informer()).
		WithInformersQueueKeyFunc(func(obj runtime.Object) string {
			accessor, _ := meta.Accessor(obj)
			return accessor.GetName()
		}, clusterInformer.Informer()).
		WithSync(c.sync).
		ToController("DefaultManagedClusterSetController", recorder)
}

func (c *defaultManagedClusterSetController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	key := syncCtx.QueueKey()

	switch {
	case len(key) == 0:
		klog.Infof("Reconciling ManagedClusterSet %s", key)
		_, err := c.clusterSetLister.Get(defaultClusterSetName)
		if errors.IsNotFound(err) {
			return c.createClusterSet(ctx, defaultClusterSetName)
		}
		if err != nil {
			return err
		}
		return nil
	}

	klog.Infof("Reconciling ManagedCluster %s", key)
	// create the defaut clusterset if it does not exist
	_, err := c.clusterSetLister.Get(defaultClusterSetName)
	if errors.IsNotFound(err) {
		return c.createClusterSet(ctx, defaultClusterSetName)
	}
	if err != nil {
		return err
	}

	// move the cluster to the defaut clusterset if it belongs to no clusterset
	cluster, err := c.clusterLister.Get(key)
	if err != nil {
		return err
	}

	if _, found := cluster.Labels[clusterSetLabel]; found {
		return nil
	}
	clusterCopy := cluster.DeepCopy()
	if len(clusterCopy.Labels) == 0 {
		clusterCopy.Labels = map[string]string{}
	}
	clusterCopy.Labels[clusterSetLabel] = defaultClusterSetName
	_, err = c.clusterClient.ClusterV1().ManagedClusters().Update(ctx, clusterCopy, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update ManagedCluster %q: %w", key, err)
	}
	return nil
}

// createClusterSet creates a cluster set with specific name
func (c *defaultManagedClusterSetController) createClusterSet(ctx context.Context, clusterSetName string) error {
	clusterSet := &clusterv1beta1.ManagedClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterSetName,
		},
	}

	_, err := c.clusterClient.ClusterV1beta1().ManagedClusterSets().Create(ctx, clusterSet, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ManagedClusterSet %q: %w", clusterSetName, err)
	}

	return nil
}
