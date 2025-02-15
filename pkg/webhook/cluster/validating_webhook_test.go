package cluster

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	clusterv1 "open-cluster-management.io/api/cluster/v1"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
	testinghelpers "open-cluster-management.io/registration/pkg/helpers/testing"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

var managedclustersSchema = metav1.GroupVersionResource{
	Group:    "cluster.open-cluster-management.io",
	Version:  "v1",
	Resource: "managedclusters",
}

func TestManagedClusterValidate(t *testing.T) {
	cases := []struct {
		name                   string
		request                *admissionv1beta1.AdmissionRequest
		expectedResponse       *admissionv1beta1.AdmissionResponse
		allowUpdateAcceptField bool
		allowUpdateClusterSets map[string]bool
	}{
		{
			name: "validate non-managedclusters request",
			request: &admissionv1beta1.AdmissionRequest{
				Resource: metav1.GroupVersionResource{
					Group:    "test.open-cluster-management.io",
					Version:  "v1",
					Resource: "tests",
				},
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name: "validate deleting operation",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Delete,
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name: "validate creating ManagedCluster",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Create,
				Object:    newManagedClusterObj(),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name: "validate creating ManagedCluster with invalid fields",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Create,
				Object:    newManagedClusterObjWithClientConfigs(clusterv1.ClientConfig{URL: "http://127.0.0.1:8001"}),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
					Message: "url \"http://127.0.0.1:8001\" is invalid in client configs",
				},
			},
		},
		{
			name: "validate creating an accepted ManagedCluster without update acceptance permission",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Create,
				Object:    newManagedClusterObjWithHubAcceptsClient(true),
				UserInfo:  authenticationv1.UserInfo{Username: "tester"},
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
					Message: "user \"tester\" cannot update the HubAcceptsClient field",
				},
			},
		},
		{
			name: "validate creating an accepted ManagedCluster",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Create,
				Object:    newManagedClusterObjWithHubAcceptsClient(true),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
			allowUpdateAcceptField: true,
		},
		{
			name: "validate update ManagedCluster without HubAcceptsClient field changed",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Update,
				OldObject: newManagedClusterObjWithClientConfigs(clusterv1.ClientConfig{URL: "https://127.0.0.1:6443"}),
				Object:    newManagedClusterObjWithClientConfigs(clusterv1.ClientConfig{URL: "https://127.0.0.1:8443"}),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name: "validate updating HubAcceptsClient field without update acceptance permission",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Update,
				OldObject: newManagedClusterObjWithHubAcceptsClient(false),
				Object:    newManagedClusterObjWithHubAcceptsClient(true),
				UserInfo:  authenticationv1.UserInfo{Username: "tester"},
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
					Message: "user \"tester\" cannot update the HubAcceptsClient field",
				},
			},
		},
		{
			name: "validate updating HubAcceptsClient field",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Update,
				OldObject: newManagedClusterObjWithHubAcceptsClient(false),
				Object:    newManagedClusterObjWithHubAcceptsClient(true),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
			allowUpdateAcceptField: true,
		},
		{
			name: "validate setting clusterset label",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Create,
				Object:    newManagedClusterObjWithClientSet("clusterset1"),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
			allowUpdateClusterSets: map[string]bool{
				"clusterset1": true,
			},
		},
		{
			name: "validate setting clusterset label without permission",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Create,
				Object:    newManagedClusterObjWithClientSet("clusterset1"),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
					Message: "user \"\" cannot add/remove a ManagedCluster to/from ManagedClusterSet \"clusterset1\"",
				},
			},
			allowUpdateClusterSets: map[string]bool{
				"clusterset1": false,
			},
		},
		{
			name: "validate updating clusterset label",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Update,
				OldObject: newManagedClusterObjWithClientSet("clusterset1"),
				Object:    newManagedClusterObjWithClientSet("clusterset2"),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
			allowUpdateClusterSets: map[string]bool{
				"clusterset1": true,
				"clusterset2": true,
			},
		},
		{
			name: "validate updating clusterset label without permission",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Update,
				OldObject: newManagedClusterObjWithClientSet("clusterset1"),
				Object:    newManagedClusterObjWithClientSet("clusterset2"),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
					Message: "user \"\" cannot add/remove a ManagedCluster to/from ManagedClusterSet \"clusterset1\"",
				},
			},
		},
		{
			name: "validate updating clusterset label with partial permission",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Update,
				OldObject: newManagedClusterObjWithClientSet("clusterset1"),
				Object:    newManagedClusterObjWithClientSet("clusterset2"),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
					Message: "user \"\" cannot add/remove a ManagedCluster to/from ManagedClusterSet \"clusterset2\"",
				},
			},
			allowUpdateClusterSets: map[string]bool{
				"clusterset1": true,
			},
		},
		{
			name: "validate resetting clusterset label",
			request: &admissionv1beta1.AdmissionRequest{
				Resource:  managedclustersSchema,
				Operation: admissionv1beta1.Update,
				OldObject: newManagedClusterObjWithClientSet("clusterset1"),
				Object:    newManagedClusterObjWithClientSet(""),
			},
			expectedResponse: &admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
			allowUpdateClusterSets: map[string]bool{
				"clusterset1": true,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kubeClient := kubefake.NewSimpleClientset()
			kubeClient.PrependReactor(
				"create",
				"subjectaccessreviews",
				func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					allowed := false

					sar := action.(clienttesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
					switch sar.Spec.ResourceAttributes.Resource {
					case "managedclusters":
						allowed = c.allowUpdateAcceptField
					case "managedclustersets":
						allowed = c.allowUpdateClusterSets[sar.Spec.ResourceAttributes.Name]
					}

					return true, &authorizationv1.SubjectAccessReview{
						Status: authorizationv1.SubjectAccessReviewStatus{
							Allowed: allowed,
						},
					}, nil
				},
			)

			admissionHook := &ManagedClusterValidatingAdmissionHook{kubeClient: kubeClient}

			actualResponse := admissionHook.Validate(c.request)

			if !reflect.DeepEqual(actualResponse, c.expectedResponse) {
				t.Errorf("expected %#v but got: %#v", c.expectedResponse.Result, actualResponse.Result)
			}
		})
	}
}

func newManagedClusterObj() runtime.RawExtension {
	managedCluster := testinghelpers.NewManagedCluster()
	clusterObj, _ := json.Marshal(managedCluster)
	return runtime.RawExtension{
		Raw: clusterObj,
	}
}

func newManagedClusterObjWithHubAcceptsClient(hubAcceptsClient bool) runtime.RawExtension {
	managedCluster := testinghelpers.NewManagedCluster()
	managedCluster.Spec.HubAcceptsClient = hubAcceptsClient
	clusterObj, _ := json.Marshal(managedCluster)
	return runtime.RawExtension{
		Raw: clusterObj,
	}
}

func newManagedClusterObjWithClientConfigs(clientConfig clusterv1.ClientConfig) runtime.RawExtension {
	managedCluster := testinghelpers.NewManagedCluster()
	managedCluster.Spec.ManagedClusterClientConfigs = []clusterv1.ClientConfig{clientConfig}
	clusterObj, _ := json.Marshal(managedCluster)
	return runtime.RawExtension{
		Raw: clusterObj,
	}
}

func newManagedClusterObjWithClientSet(clusterSetName string) runtime.RawExtension {
	managedCluster := testinghelpers.NewManagedCluster()
	managedCluster.Labels = map[string]string{
		clusterSetLabel: clusterSetName,
	}
	clusterObj, _ := json.Marshal(managedCluster)
	return runtime.RawExtension{
		Raw: clusterObj,
	}
}

func newManagedClusterSet(name string) *clusterv1beta1.ManagedClusterSet {
	return &clusterv1beta1.ManagedClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}
