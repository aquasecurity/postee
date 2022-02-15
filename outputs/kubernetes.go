package outputs

import (
	"context"
	"log"

	"github.com/aquasecurity/postee/v2/layout"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesClient struct {
	clientset kubernetes.Interface

	Name              string
	KubeConfigFile    string
	KubeLabels        map[string]string
	KubeLabelSelector string
	KubeAnnotations   map[string]string
	KubeConfigMap     map[string]string
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
	pods, _ := k.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: k.KubeLabelSelector,
	})

	// TODO: Set configmap
	for _, pod := range pods.Items { // TODO: Allow configuring of resource {pod, ds, ...}
		if len(k.KubeLabels) > 0 {
			labels := make(map[string]string)
			oldLabels := pod.GetLabels()
			for k, v := range oldLabels {
				labels[k] = v
			}
			for k, v := range k.KubeLabels {
				labels[k] = v
			}

			pod.SetLabels(labels)
			_, err := k.clientset.CoreV1().Pods(pod.GetNamespace()).Update(ctx, &pod, metav1.UpdateOptions{})
			if err != nil {
				log.Println("failed to apply labels to pod:", pod.Name, "err:", err.Error())
			} else {
				log.Println("labels applied successfully to pod:", pod.Name)
			}
		}

		if len(k.KubeAnnotations) > 0 {
			annotations := make(map[string]string)
			oldAnnotations := pod.GetAnnotations()
			for k, v := range oldAnnotations {
				annotations[k] = v
			}
			for k, v := range k.KubeAnnotations {
				annotations[k] = v
			}

			pod.SetAnnotations(annotations)
			_, err := k.clientset.CoreV1().Pods(pod.GetNamespace()).Update(ctx, &pod, metav1.UpdateOptions{})
			if err != nil {
				log.Println("failed to apply annotation to pod:", pod.Name, "err:", err.Error())
			} else {
				log.Println("annotations applied successfully to pod:", pod.Name)
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
