package audit

import (
	"testing"

	"github.com/pjbgf/go-test/should"
)

func Test_IsAuditLine(t *testing.T) {
	assertThat := func(assumption, auditLine string, expected bool) {
		should := should.New(t)

		actual := IsAuditLine(auditLine)

		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should identify seccomp log lines",
		`audit: type=1326 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=615549 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f61a81c5923 code=0x7ffc0000`,
		true)
	assertThat("should ignore unsupported log types",
		`audit: type=1016 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=615549 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f61a81c5923 code=0x7ffc0000`,
		false)
	assertThat("should ignore unsupported log",
		`type=1326 syscall=1`,
		false)
}

func Test_ExtractAuditLine(t *testing.T) {
	assertThat := func(assumption, auditLine string, expectedAudit *AuditLine, expectedErr error) {
		should := should.New(t)

		actual, actualErr := ExtractAuditLine(auditLine)

		should.BeEqual(expectedAudit, actual, assumption)
		should.BeEqual(expectedErr, actualErr, assumption)
	}

	assertThat("should identify seccomp log lines",
		`audit: type=1326 audit(1612299677.115:549067): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=3109464 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=0 compat=0 ip=0x7fce771ae923 code=0x7ffc0000`,
		&AuditLine{
			Type:         "seccomp",
			TimestampID:  "1612299677.115:549067",
			SystemCallID: 0,
			ProcessID:    3109464,
			Executable:   "/bin/busybox",
		},
		nil)
}
