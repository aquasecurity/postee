package actions

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

func TestKubernetesClientSend_Labels(t *testing.T) {
	testCases := []struct {
		name               string
		inputEvent         string
		reactorFunc        func(k8stesting.Action) (bool, runtime.Object, error)
		inputActions       map[string]map[string]string
		inputLabelSelector string
		expectedLabels     map[string]string
	}{
		{
			name:       "happy path, labels are added",
			inputEvent: `{"SigMetadata":{"ID":"TRC-2"}}`,
			inputActions: map[string]map[string]string{
				"labels": {"foo": "bar"},
			},
			inputLabelSelector: "app=nginx",
			expectedLabels: map[string]string{
				"app": "nginx",
				"foo": "bar",
			},
		},
		{
			name:       "happy path, relative label selector and labels are added",
			inputEvent: `{"SigMetadata":{"ID":"TRC-2", "Hostname":"nginx"}}`,
			inputActions: map[string]map[string]string{
				"labels": {"foo": "bar"},
			},
			inputLabelSelector: "app=event.input.SigMetadata.Hostname",
			expectedLabels: map[string]string{
				"app": "nginx",
				"foo": "bar",
			},
		},
		{
			name:       "happy path, json input event, relative input labels are added",
			inputEvent: `{"SigMetadata":{"ID":"TRC-2", "Hostname":"foo.com"}}`,
			inputActions: map[string]map[string]string{
				"labels": {
					"foo":      "event.input.SigMetadata.ID",
					"hostname": "event.input.SigMetadata.Hostname",
				},
			},
			inputLabelSelector: "app=nginx",
			expectedLabels: map[string]string{
				"app":      "nginx",
				"foo":      "TRC-2",
				"hostname": "foo.com",
			},
		},
		{
			name:       "happy path, string input event, relative input labels are added",
			inputEvent: `foo bar baz`,
			inputActions: map[string]map[string]string{
				"labels": {"foo": "event.input"},
			},
			inputLabelSelector: "app=nginx",
			expectedLabels: map[string]string{
				"app": "nginx",
				"foo": "foo bar baz",
			},
		},
		{
			name:               "sad path, unable to add label",
			inputEvent:         `{"SigMetadata":{"ID":"TRC-2"}}`,
			inputLabelSelector: "app=nginx",
			reactorFunc: func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				return true, nil, fmt.Errorf("failed to update label")
			},
			expectedLabels: map[string]string{
				"app": "nginx",
			},
		},
		{
			name:       "sad path, no matching label selector and no labels are added",
			inputEvent: `{"SigMetadata":{"ID":"TRC-2"}}`,
			inputActions: map[string]map[string]string{
				"labels": {"foo": "bar"},
			},
			inputLabelSelector: "app=doesntexist",
			expectedLabels: map[string]string{
				"app": "nginx",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := KubernetesClient{
				clientset:         fake.NewSimpleClientset(),
				KubeNamespace:     "testing",
				KubeActions:       tc.inputActions,
				KubeLabelSelector: tc.inputLabelSelector,
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
			require.NoError(t, k.Send(map[string]string{"description": tc.inputEvent}), tc.name)

			pods, _ := k.clientset.CoreV1().Pods("testing").Get(context.TODO(), "test-pod", metav1.GetOptions{})
			assert.Equal(t, tc.expectedLabels, pods.Labels, tc.name)
		})
	}
}

func TestKubernetesClientSend_Annotations(t *testing.T) {
	testCases := []struct {
		name                string
		inputEvent          string
		reactorFunc         func(k8stesting.Action) (bool, runtime.Object, error)
		inputActions        map[string]map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name:       "happy path, labels are added",
			inputEvent: `{"SigMetadata":{"ID":"TRC-2"}}`,
			inputActions: map[string]map[string]string{
				"annotations": {"foo": "bar"},
			},
			expectedAnnotations: map[string]string{
				"app": "nginx",
				"foo": "bar",
			},
		},
		{
			name:       "happy path, json input event, relative input annotations are added",
			inputEvent: `{"SigMetadata":{"ID":"TRC-2"}}`,
			inputActions: map[string]map[string]string{
				"annotations": {"foo": "event.input.SigMetadata.ID"},
			},
			expectedAnnotations: map[string]string{
				"app": "nginx",
				"foo": "TRC-2",
			},
		},
		{
			name:       "happy path, string input event, relative input annotations are added",
			inputEvent: `foo bar baz`,
			inputActions: map[string]map[string]string{
				"annotations": {"foo": "event.input"},
			},
			expectedAnnotations: map[string]string{
				"app": "nginx",
				"foo": "foo bar baz",
			},
		},
		{
			name:       "sad path, unable to add annotations",
			inputEvent: `{"SigMetadata":{"ID":"TRC-2"}}`,
			reactorFunc: func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				return true, nil, fmt.Errorf("failed to update label")
			},
			expectedAnnotations: map[string]string{
				"app": "nginx",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := KubernetesClient{
				clientset:     fake.NewSimpleClientset(),
				KubeNamespace: "testing",
				KubeActions:   tc.inputActions,
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
			require.NoError(t, k.Send(map[string]string{"description": tc.inputEvent}), tc.name)

			pods, _ := k.clientset.CoreV1().Pods("testing").Get(context.TODO(), "test-pod", metav1.GetOptions{})
			assert.Equal(t, tc.expectedAnnotations, pods.Annotations, tc.name)
		})
	}
}
