package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/pjbgf/go-sample-console-app/pkg/calc"
)

// Console represents a Console application.
type Console struct {
	commandFactory func(args []string) (cliCommand, error)
	stdOut         io.Writer
	stdErr         io.Writer
	exit           func(code int)
}

type cliCommand interface {
	run(output io.Writer)
}

// NewConsole initialise and return a new Console object.
func NewConsole(stdOut io.Writer, stdErr io.Writer, exit func(int)) *Console {
	if stdOut == (*bytes.Buffer)(nil) {
		panic("stdOut was null")
	}
	if stdErr == (*bytes.Buffer)(nil) {
		panic("stdErr was null")
	}

	return &Console{
		getCommand,
		stdOut,
		stdErr,
		exit,
	}
}

func (c *Console) exitOnError(writer io.Writer, err error) {
	printf(writer, "error: %s\n", err)

	c.exit(5)
}

// Run runs the console application.
func (c *Console) Run(args []string) {
	cmd, err := c.commandFactory(args)
	if err != nil {
		c.exitOnError(c.stdErr, err)
	} else {
		cmd.run(c.stdOut)
	}
}

func getCommand(args []string) (cliCommand, error) {
	val1, val2, op, err := parse(args)
	if err != nil {
		return nil, err
	}

	if op == "+" {
		return &additionCommand{val1, val2}, nil
	}

	return nil, errors.New("invalid operation")
}

func parse(args []string) (value1, value2 int, op string, err error) {
	if len(args) < 4 {
		err = errors.New("invalid syntax")
		return
	}

	if value1, err = strconv.Atoi(args[1]); err != nil {
		err = fmt.Errorf("'%s' is not valid for value1", args[1])
		return
	}

	op = args[2]

	if value2, err = strconv.Atoi(args[3]); err != nil {
		err = fmt.Errorf("'%s' is not valid for value2", args[3])
		return
	}

	return
}

type additionCommand struct {
	value1, value2 int
}

func (a *additionCommand) run(output io.Writer) {
	v := calc.Sum(a.value1, a.value2)

	printf(output, "sum total: %d\n", v)
}

func printf(writer io.Writer, format string, args ...interface{}) {
	_, _ = writer.Write([]byte(fmt.Sprintf(format, args...)))
}
