package audit

import (
	"fmt"
	"regexp"
	"strconv"
)

var (
	// Initially only seccomp logs  are supported
	// type IDs are defined at https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/audit.h
	auditRegex = regexp.MustCompile(`audit:.+type=1326.+audit\((.+)\).+pid=(\b\d+\b).+exe="(.+)".+syscall=(\b\d+\b).*`)
)

// IsAuditLine checks whether logLine is a supported audit line
func IsAuditLine(logLine string) bool {
	captures := auditRegex.FindStringSubmatch(logLine)

	return captures != nil && len(captures) > 1
}

// ExtractAuditLine extracts an auditline from logLine
func ExtractAuditLine(logLine string) (*AuditLine, error) {
	captures := auditRegex.FindStringSubmatch(logLine)
	if captures == nil || len(captures) < 5 {
		return nil, fmt.Errorf("extract audit line: %s", logLine)
	}

	line := AuditLine{}
	line.Type = "seccomp"
	line.TimestampID = captures[1]
	line.Executable = captures[3]
	if v, err := strconv.Atoi(captures[2]); err == nil {
		line.ProcessID = v
	}
	if v, err := strconv.Atoi(captures[4]); err == nil {
		line.SystemCallID = v
	}

	return &line, nil
}
