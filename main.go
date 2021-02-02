package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/pjbgf/kube-audit-log-enricher/pkg/audit"
	"github.com/pjbgf/kube-audit-log-enricher/pkg/kube"
	"k8s.io/klog/klogr"

	"github.com/cirocosta/dmesg_exporter/kmsg"
	"github.com/cirocosta/dmesg_exporter/reader"
)

var (
	logFile = "/dev/kmsg"
	logger  logr.Logger
)

func main() {
	logger := klogr.New().WithName("log-exporter")
	nodeName := os.Getenv("NODE_NAME")
	if len(nodeName) == 0 {
		logger.Error(nil, "'NODE_NAME' environment variable not found")
		os.Exit(1)
	}

	logger.V(1).Info("starting log-exporter on node: ", nodeName)

	auditLines := make(chan string)
	go tailDevice(logFile, auditLines)

	for {
		line := <-auditLines
		if audit.IsAuditLine(line) {
			auditLine, err := audit.ExtractAuditLine(line)
			if err != nil {
				fmt.Printf("extract seccomp details from audit line: %v\n", err)
			}

			if auditLine.SystemCallID == 0 {
				logger.V(5).Info("skip line with systemCallID 0", "processID", auditLine.ProcessID)
				continue
			}

			cID := getContainerID(auditLine.ProcessID)
			containers, err := kube.GetNodeContainers(nodeName)
			c, found := containers[cID]

			if !found {
				logger.Error(err, "containerID not found", "processID", auditLine.ProcessID)
				continue
			}

			name := audit.SystemCalls[auditLine.SystemCallID]
			fmt.Printf("audit(%s) type=%s node=%s pid=%d ns=%s pod=%s c=%s exe=%s syscall=%s\n",
				auditLine.TimestampID, auditLine.Type, nodeName, auditLine.ProcessID, c.Namespace, c.PodName, c.ContainerName, auditLine.Executable, name)
		}
	}
}

func blockAndCancelOnSignal(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	cancel()
}

func tailDevice(device string, msgs chan string) {
	file, err := os.Open(device)
	if err != nil {
		return
	}
	defer file.Close()

	// seek to the end of device
	_, err = file.Seek(0, os.SEEK_END)
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go blockAndCancelOnSignal(cancel)

	var (
		r        = reader.NewReader(file)
		messages = make(chan *kmsg.Message, 1)
	)

	kmsgErrorsChan := r.Listen(ctx, messages)

	for {
		select {
		case err = <-kmsgErrorsChan:
			return
		case message := <-messages:
			if message == nil {
				return
			}

			if message.Facility != kmsg.FacilityKern {
				continue
			}

			msgs <- message.Message
		}
	}
}

func getContainerID(processID int) string {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", processID)
	file, err := os.Open(filepath.Clean(cgroupFile))
	if err != nil {
		logger.V(8).Info("could not open cgroup", "process-id", processID)
		return ""
	}
	defer func() {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
	}()

	// extracts crio format from cgroup:
	// 0::/system.slice/crio-conmon-5819a498721cf8bb7e334809c9e48aa310bfc98801eb8017034ad17fb0749920.scope
	podIDRegex := regexp.MustCompile(`^0.+-([a-f0-9]+)\.scope$`)
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		capture := podIDRegex.FindStringSubmatch(scanner.Text())
		if capture != nil && len(capture) > 0 {
			return capture[1]
		}
	}
	return ""
}
