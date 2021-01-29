package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestNewConsole(t *testing.T) {
	assertThat := func(assumption string, stdOut, stdErr *bytes.Buffer, shouldError bool) {
		should := should.New(t)
		hasErrored := false

		defer func() {
			if r := recover(); r != nil {
				hasErrored = true
			}
		}()

		NewConsole(stdOut, stdErr, func(int) {})

		should.BeEqual(shouldError, hasErrored, assumption)
	}

	var stdOut, stdErr bytes.Buffer
	assertThat("should panic for nil stdOut", nil, &stdErr, true)
	assertThat("should panic for nil stdErr", &stdOut, nil, true)
	assertThat("should not panic if stdErr and stdOut are not nil", &stdOut, &stdErr, false)
}

type commandStub struct {
	hasExecuted bool
}

func (c *commandStub) run(output io.Writer) {
	c.hasExecuted = true
}

func TestRun(t *testing.T) {
	assertThat := func(assumption string, err error, errored, executedCmd bool) {
		should := should.New(t)
		var (
			hasErrored     bool = false
			stdOut, stdErr bytes.Buffer
		)
		stub := &commandStub{}
		c := NewConsole(&stdOut, &stdErr, func(code int) { hasErrored = true })
		c.commandFactory = func(args []string) (cliCommand, error) {
			return stub, err
		}

		c.Run([]string{})

		should.BeEqual(errored, hasErrored, assumption)
		should.BeEqual(executedCmd, stub.hasExecuted, assumption)
	}

	assertThat("should not run command when get error", errors.New("some error"), true, false)
	assertThat("should run command when no errors", nil, false, true)
}

func TestGetCommand(t *testing.T) {
	assertThat := func(assumption string, command string, expectedCmd cliCommand, expectedErr error) {
		should := should.New(t)

		actualCmd, actualErr := getCommand(strings.Split(command, " "))

		should.BeEqual(expectedErr, actualErr, assumption)
		should.HaveSameType(expectedCmd, actualCmd, assumption)
	}

	assertThat("should return additionCommand for 'calc 1 + 1'", "calc 1 + 1", &additionCommand{}, nil)
	assertThat("should error for 'calc 1 +'", "calc 1 +", nil, errors.New("invalid syntax"))
	assertThat("should error for invalid operations 'calc 1 # 1'", "calc 1 # 1", nil, errors.New("invalid operation"))
}

func TestParse(t *testing.T) {
	assertThat := func(assumption string, command string,
		expectedVal1, expectedVal2 int, expectedOp string, expectedErr error) {
		should := should.New(t)
		args := strings.Split(command, " ")

		val1, val2, op, err := parse(args)

		should.BeEqual(expectedErr, err, assumption)
		should.HaveSameType(expectedVal1, val1, assumption)
		should.HaveSameType(expectedVal2, val2, assumption)
		should.HaveSameType(expectedOp, op, assumption)
	}

	assertThat("should parse each arg from 'calc 1 + 5'", "calc 1 + 5",
		1, 5, "+", nil)
	assertThat("should error when first value is invalid 'calc a + 1'", "calc a + 1",
		0, 0, "", errors.New("'a' is not valid for value1"))
	assertThat("should error when first value is invalid 'calc 1 + f'", "calc 1 + f",
		0, 0, "", errors.New("'f' is not valid for value2"))
}

func TestAdditionCommand(t *testing.T) {
	assertThat := func(assumption string, v1, v2 int, expectedOutput string) {
		should := should.New(t)
		cmd := additionCommand{v1, v2}
		var stdOut bytes.Buffer

		cmd.run(&stdOut)

		actualOutput := stdOut.String()

		should.BeEqual(expectedOutput, actualOutput, assumption)
	}

	assertThat("should print 'sum total: 5\n' for 3 + 2", 3, 2, "sum total: 5\n")
	assertThat("should print 'sum total: 79\n' for 40 + 39", 40, 39, "sum total: 79\n")
}
