package outputs

import (
	"context"
	"fmt"
	"log"

	"github.com/aquasecurity/postee/v2/layout"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

type KubernetesClient struct {
	clientset kubernetes.Interface

	Name              string
	KubeNamespace     string
	KubeConfigFile    string
	KubeLabels        map[string]string
	KubeLabelSelector string
	KubeAnnotations   map[string]string
}

func (k KubernetesClient) GetName() string {
	return k.Name
}

func (k *KubernetesClient) Init() error {
	config, err := clientcmd.BuildConfigFromFlags("", k.KubeConfigFile)
	if err != nil {
		log.Println("unable to initialize kubernetes config: ", err)
		return err
	}

	k.clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Println("unable to initialize kubernetes client: ", err)
		return err
	}

	return nil
}

func (k KubernetesClient) Send(m map[string]string) error {
	ctx := context.Background()

	if k.KubeNamespace == "" {
		return fmt.Errorf("kubernetes namespace needs to be set in config.yaml")
	}

	// TODO: Allow configuring of resource {pod, ds, ...}
	// TODO: Allow input of resource name
	pods, _ := k.clientset.CoreV1().Pods(k.KubeNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: k.KubeLabelSelector,
	})
	for _, pod := range pods.Items {
		if len(k.KubeLabels) > 0 {
			retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				pod, err := k.clientset.CoreV1().Pods(pod.GetNamespace()).Get(ctx, pod.Name, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get updated pod for labeling: %s, err: %w", pod.Name, err)
				}

				labels := make(map[string]string)
				oldLabels := pod.GetLabels()
				for k, v := range oldLabels {
					labels[k] = v
				}
				for k, v := range k.KubeLabels {
					labels[k] = v
				}

				pod.SetLabels(labels)
				_, err = k.clientset.CoreV1().Pods(pod.GetNamespace()).Update(ctx, pod, metav1.UpdateOptions{})
				if err != nil {
					log.Println("failed to apply labels to pod:", pod.Name, "err:", err.Error(), "retrying...")
					return err
				} else {
					log.Println("labels applied successfully to pod:", pod.Name)
				}
				return nil
			})
			if retryErr != nil {
				log.Println("failed to apply labels to pod:", pod.Name, "err:", retryErr)
			}
		}

		if len(k.KubeAnnotations) > 0 {
			retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				pod, err := k.clientset.CoreV1().Pods(pod.GetNamespace()).Get(ctx, pod.Name, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get updated pod for annotating: %s, err: %w", pod.Name, err)
				}
				annotations := make(map[string]string)
				oldAnnotations := pod.GetAnnotations()
				for k, v := range oldAnnotations {
					annotations[k] = v
				}
				for k, v := range k.KubeAnnotations {
					annotations[k] = v
				}

				pod.SetAnnotations(annotations)
				_, err = k.clientset.CoreV1().Pods(pod.GetNamespace()).Update(ctx, pod, metav1.UpdateOptions{})
				if err != nil {
					log.Println("failed to apply annotation to pod:", pod.Name, "err:", err.Error(), "retrying...")
					return err
				} else {
					log.Println("annotations applied successfully to pod:", pod.Name)
				}
				return nil
			})
			if retryErr != nil {
				log.Println("failed to apply annotations to pod:", pod.Name, "err:", retryErr)
			}
		}
	}
	return nil
}

func (k KubernetesClient) Terminate() error {
	log.Printf("Kubernetes output terminated\n")
	return nil
}

func (k KubernetesClient) GetLayoutProvider() layout.LayoutProvider {
	return nil
}
