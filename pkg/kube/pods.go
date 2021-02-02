package kube

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/pjbgf/kube-audit-log-enricher/pkg/audit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	crioPrefix = "cri-o://"
)

func GetNodeContainers(nodeName string) (map[string]audit.Container, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("get in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config: %v", err)
	}

	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return nil, fmt.Errorf("list node %s's pods: %v", nodeName, err)
	}

	containers := make(map[string]audit.Container)
	for _, pod := range pods.Items {
		for _, c := range pod.Status.ContainerStatuses {
			containerID, err := containerIDRaw(c.ContainerID)
			if err != nil {
				return nil, fmt.Errorf("container id: %v", err)
			}

			containers[containerID] = audit.Container{
				PodName:       pod.Name,
				ContainerName: c.Name,
				Namespace:     pod.Namespace,
				ContainerID:   containerID,
			}
		}
	}
	return containers, nil
}

func containerIDRaw(containerID string) (string, error) {
	if strings.Contains(containerID, crioPrefix) {
		return strings.TrimPrefix(containerID, crioPrefix), nil
	}

	return "", fmt.Errorf("unsupported container ID: %s", containerID)
}
