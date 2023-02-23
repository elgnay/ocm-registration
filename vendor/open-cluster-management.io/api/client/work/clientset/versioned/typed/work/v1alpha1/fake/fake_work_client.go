// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
	v1alpha1 "open-cluster-management.io/api/client/work/clientset/versioned/typed/work/v1alpha1"
)

type FakeWorkV1alpha1 struct {
	*testing.Fake
}

func (c *FakeWorkV1alpha1) PlaceManifestWorks(namespace string) v1alpha1.PlaceManifestWorkInterface {
	return &FakePlaceManifestWorks{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeWorkV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
