package outputs

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	fake2 "k8s.io/client-go/kubernetes/typed/core/v1/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestKubernetesClient_Send(t *testing.T) {
	t.Run("labels", func(t *testing.T) {
		testCases := []struct {
			name           string
			reactorFunc    func(k8stesting.Action) (bool, runtime.Object, error)
			expectedLabels map[string]string
		}{
			{
				name: "happy path, labels are added",
				expectedLabels: map[string]string{
					"app": "nginx",
					"foo": "bar",
				},
			},
			{
				name: "sad path, unable to add label",
				reactorFunc: func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("failed to update label")
				},
				expectedLabels: map[string]string{
					"app": "nginx",
				},
			},
		}

		for _, tc := range testCases {
			k := KubernetesClient{
				clientset:     fake.NewSimpleClientset(),
				KubeNamespace: "testing",
				KubeLabels: map[string]string{
					"foo": "bar",
				},
				KubeLabelSelector: "app=nginx",
			}

			if tc.reactorFunc != nil {
				k.clientset.CoreV1().(*fake2.FakeCoreV1).Fake.PrependReactor("update", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("failed to update label")
				})
			}

			pod := &v1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "testing",
					Labels:    map[string]string{"app": "nginx"},
				},
			}

			_, err := k.clientset.CoreV1().Pods("testing").Create(context.TODO(), pod, metav1.CreateOptions{})
			require.NoError(t, err, tc.name)
			require.NoError(t, k.Send(nil), tc.name)

			pods, _ := k.clientset.CoreV1().Pods("testing").Get(context.TODO(), "test-pod", metav1.GetOptions{})
			assert.Equal(t, tc.expectedLabels, pods.Labels, tc.name)
		}

	})

	t.Run("annotations", func(t *testing.T) {
		testCases := []struct {
			name                string
			reactorFunc         func(k8stesting.Action) (bool, runtime.Object, error)
			expectedAnnotations map[string]string
		}{
			{
				name: "happy path, labels are added",
				expectedAnnotations: map[string]string{
					"app": "nginx",
					"foo": "bar",
				},
			},
			{
				name: "sad path, unable to add annotations",
				reactorFunc: func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("failed to update label")
				},
				expectedAnnotations: map[string]string{
					"app": "nginx",
				},
			},
		}

		for _, tc := range testCases {
			k := KubernetesClient{
				clientset:     fake.NewSimpleClientset(),
				KubeNamespace: "testing",
				KubeAnnotations: map[string]string{
					"foo": "bar",
				},
			}

			if tc.reactorFunc != nil {
				k.clientset.CoreV1().(*fake2.FakeCoreV1).Fake.PrependReactor("update", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("failed to update annotation")
				})
			}
			pod := &v1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-pod",
					Namespace:   "testing",
					Annotations: map[string]string{"app": "nginx"},
				},
			}

			_, err := k.clientset.CoreV1().Pods("testing").Create(context.TODO(), pod, metav1.CreateOptions{})
			require.NoError(t, err, tc.name)
			require.NoError(t, k.Send(nil), tc.name)

			pods, _ := k.clientset.CoreV1().Pods("testing").Get(context.TODO(), "test-pod", metav1.GetOptions{})
			assert.Equal(t, tc.expectedAnnotations, pods.Annotations, tc.name)
		}
	})
}
