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
	t.Run("happy path", func(t *testing.T) {
		k := KubernetesClient{
			clientset: fake.NewSimpleClientset(),
			KubeLabels: map[string]string{
				"foo": "bar",
			},
			KubeLabelSelector: "app=nginx",
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
		require.NoError(t, err)
		require.NoError(t, k.Send(map[string]string{"foo": "bar"}))

		pods, _ := k.clientset.CoreV1().Pods("testing").Get(context.TODO(), "test-pod", metav1.GetOptions{})
		assert.Equal(t, map[string]string{"app": "nginx", "foo": "bar"}, pods.Labels)
	})

	t.Run("sad path, unable to apply label", func(t *testing.T) {
		k := KubernetesClient{
			clientset: fake.NewSimpleClientset(),
			KubeLabels: map[string]string{
				"foo": "bar",
			},
			KubeLabelSelector: "app=nginx",
		}
		k.clientset.CoreV1().(*fake2.FakeCoreV1).Fake.PrependReactor("patch", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("failed to update label")
		})

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
		require.NoError(t, err)

		require.NoError(t, k.Send(map[string]string{"foo": "bar"}))

		pods, _ := k.clientset.CoreV1().Pods("testing").Get(context.TODO(), "test-pod", metav1.GetOptions{})
		assert.Equal(t, map[string]string{"app": "nginx"}, pods.Labels)
	})
}
