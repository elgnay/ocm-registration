package managedclusterset

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	clientset "open-cluster-management.io/api/client/cluster/clientset/versioned"
	clusterinformerv1 "open-cluster-management.io/api/client/cluster/informers/externalversions/cluster/v1"
	clusterinformerv1beta1 "open-cluster-management.io/api/client/cluster/informers/externalversions/cluster/v1beta1"
	clusterlisterv1 "open-cluster-management.io/api/client/cluster/listers/cluster/v1"
	clusterlisterv1beta1 "open-cluster-management.io/api/client/cluster/listers/cluster/v1beta1"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
)

const (
	clusterSetLabel = "cluster.open-cluster-management.io/clusterset"
)

// managedClusterSetController reconciles instances of ManagedClusterSet on the hub.
type managedClusterSetController struct {
	clusterClient    clientset.Interface
	clusterLister    clusterlisterv1.ManagedClusterLister
	clusterSetLister clusterlisterv1beta1.ManagedClusterSetLister
	eventRecorder    events.Recorder

	// clusterSetsMap caches the mappings between clusters and clustersets.
	// With the mappings, it's easy to find out which clustersets are impacted on a
	// change of cluster.
	clusterSetsMap map[string]sets.String
	mapLock        sync.Mutex
}

// NewManagedClusterSetController creates a new managed cluster set controller
func NewManagedClusterSetController(
	clusterClient clientset.Interface,
	clusterInformer clusterinformerv1.ManagedClusterInformer,
	clusterSetInformer clusterinformerv1beta1.ManagedClusterSetInformer,
	recorder events.Recorder) factory.Controller {
	syncCtx := factory.NewSyncContext("managed-cluster-set-controller", recorder)
	enqueue := func(clustersets ...string) {
		for _, clusterset := range clustersets {
			syncCtx.Queue().Add(clusterset)
		}
	}
	c := &managedClusterSetController{
		clusterClient:    clusterClient,
		clusterLister:    clusterInformer.Lister(),
		clusterSetLister: clusterSetInformer.Lister(),
		eventRecorder:    recorder.WithComponentSuffix("managed-cluster-set-controller"),
	}

	clusterInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.onClusterSetChange(obj, enqueue)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.onClusterSetChange(newObj, enqueue)
		},
		DeleteFunc: func(obj interface{}) {
			var clusterName string
			switch t := obj.(type) {
			case *clusterv1.ManagedCluster:
				clusterName = t.Name
			case cache.DeletedFinalStateUnknown:
				cluster, ok := t.Obj.(metav1.Object)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
					return
				}
				clusterName = cluster.GetName()
			default:
				utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
				return
			}

			if clusterSets, ok := c.clusterSetsMap[clusterName]; ok {
				c.mapLock.Lock()
				defer c.mapLock.Unlock()
				delete(c.clusterSetsMap, clusterName)
				enqueue(clusterSets.List()...)
			}
		},
	})

	return factory.New().
		WithInformersQueueKeyFunc(func(obj runtime.Object) string {
			accessor, _ := meta.Accessor(obj)
			return accessor.GetName()
		}, clusterSetInformer.Informer()).
		WithBareInformers(clusterInformer.Informer()).
		WithSync(c.sync).
		ToController("ManagedClusterSetController", recorder)
}

func (c *managedClusterSetController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	clusterSetName := syncCtx.QueueKey()
	if len(clusterSetName) == 0 {
		return nil
	}
	klog.Infof("Reconciling ManagedClusterSet %s", clusterSetName)

	clusterSet, err := c.clusterSetLister.Get(clusterSetName)
	if errors.IsNotFound(err) {
		// cluster set not found, could have been deleted, do nothing.
		return nil
	}
	if err != nil {
		return err
	}

	// no work to do if the cluster set is deleted
	if !clusterSet.DeletionTimestamp.IsZero() {
		return nil
	}

	if err := c.syncClusterSet(ctx, clusterSet); err != nil {
		return fmt.Errorf("failed to sync ManagedClusterSet %q: %w", clusterSetName, err)
	}
	return nil
}

// syncClusterSet syncs a particular cluster set
func (c *managedClusterSetController) syncClusterSet(ctx context.Context, originalClusterSet *clusterv1beta1.ManagedClusterSet) error {
	clusterSet := originalClusterSet.DeepCopy()

	labelKey, labelValue := clusterSetLabel, clusterSet.Name
	if len(clusterSet.Spec.ExclusiveKey) != 0 {
		labelKey = clusterSet.Spec.ExclusiveKey
	}
	if len(clusterSet.Spec.ExclusiveValue) != 0 {
		labelValue = clusterSet.Spec.ExclusiveValue
	}

	// find out the containing clusters of clusterset
	selector := labels.SelectorFromSet(labels.Set{
		labelKey: labelValue,
	})
	clusters, err := c.clusterLister.List(selector)
	if err != nil {
		return fmt.Errorf("failed to list ManagedClusters: %w", err)
	}

	// update clusterset status
	clusterSet.Status.NumberOfSelectedClusters = int32(len(clusters))

	emptyCondition := metav1.Condition{
		Type: clusterv1beta1.ManagedClusterSetConditionEmpty,
	}
	if count := len(clusters); count == 0 {
		emptyCondition.Status = metav1.ConditionTrue
		emptyCondition.Reason = "NoClusterMatched"
		emptyCondition.Message = "No ManagedCluster selected"
	} else {
		emptyCondition.Status = metav1.ConditionFalse
		emptyCondition.Reason = "ClustersSelected"
		emptyCondition.Message = fmt.Sprintf("%d ManagedClusters selected", count)
	}
	meta.SetStatusCondition(&clusterSet.Status.Conditions, emptyCondition)

	// skip update if cluster set status does not change
	if reflect.DeepEqual(clusterSet.Status, originalClusterSet.Status) {
		return nil
	}

	_, err = c.clusterClient.ClusterV1beta1().ManagedClusterSets().UpdateStatus(ctx, clusterSet, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update status of ManagedClusterSet %q: %w", clusterSet.Name, err)
	}

	return nil
}

func (c *managedClusterSetController) onClusterSetChange(obj interface{}, enqueue func(clustersets ...string)) {
	cluster, ok := obj.(*clusterv1.ManagedCluster)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
		return
	}

	clustersets, err := c.clusterSetLister.List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error listing clustersets: %w", err))
	}

	currentClusterSets := sets.NewString()
	for _, clusterset := range clustersets {
		if isMemberOf(cluster, clusterset) {
			currentClusterSets.Insert(clusterset.Name)
		}
	}

	impacted := currentClusterSets
	c.mapLock.Lock()
	defer c.mapLock.Unlock()
	orignialClusterSets, ok := c.clusterSetsMap[cluster.Name]
	if ok {
		impacted = currentClusterSets.Union(orignialClusterSets)
	}
	c.clusterSetsMap[cluster.Name] = currentClusterSets
	enqueue(impacted.List()...)
}

func isMemberOf(cluster *clusterv1.ManagedCluster, clusterSet *clusterv1beta1.ManagedClusterSet) bool {
	key, value := clusterSetLabel, clusterSet.Name
	if len(clusterSet.Spec.ExclusiveKey) != 0 {
		key = clusterSet.Spec.ExclusiveKey
	}
	if len(clusterSet.Spec.ExclusiveValue) != 0 {
		value = clusterSet.Spec.ExclusiveValue
	}

	return cluster.Labels[key] == value
}
