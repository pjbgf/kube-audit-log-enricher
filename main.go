package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/go-logr/logr"
	"github.com/pjbgf/kube-audit-log-enricher/pkg/audit"
	"github.com/pjbgf/kube-audit-log-enricher/pkg/kube"
	"k8s.io/klog/klogr"
)

var (
	logFile = "/var/log/syslog"
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
	go tail(logFile, auditLines)

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

func tail(filePath string, lines chan string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file '%s': %v", filePath, err)
	}
	defer file.Close()

	offset, err := file.Seek(0, io.SeekEnd)
	buffer := make([]byte, 1024, 1024)
	for {
		readBytes, err := file.ReadAt(buffer, offset)
		if err != nil {
			if err != io.EOF {
				return fmt.Errorf("read buffer: %v", err)
			}
		}
		offset += int64(readBytes)
		if readBytes != 0 {
			lines <- string(buffer[:readBytes])
		}
		time.Sleep(time.Second)
	}
}

func getContainerID(processID int) string {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", processID)
	file, err := os.Open(cgroupFile)
	if err != nil {
		logger.V(8).Info("could not open cgroup", "process-id", processID)
		return ""
	}
	defer file.Close()

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
