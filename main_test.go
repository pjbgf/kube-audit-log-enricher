package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestMain_E2E(t *testing.T) {
	assertThat := func(assumption, command, expectedOutput string) {
		should := should.New(t)
		stdout, _ := ioutil.TempFile("", "calc-fake-stdout.*")
		defer os.Remove(stdout.Name())

		os.Stdout = stdout
		os.Args = strings.Split(command, " ")

		main()

		output, err := ioutil.ReadFile(stdout.Name())
		actualOutput := string(output)

		should.NotError(err, assumption)
		should.BeEqual(expectedOutput, actualOutput, assumption)
	}

	assertThat("should sum 1+1 and return 2", "calc 1 + 1", "sum total: 2\n")
}

func TestMain_ErrorCodes(t *testing.T) {
	assertThat := func(assumption, command, expectedErr, expectedOutput string) {
		should := should.New(t)
		exe, _ := os.Executable()

		cmd := exec.Command(exe, "-test.run", "^TestMain_ErrorCodes_Inception$")
		cmd.Env = append(cmd.Env, fmt.Sprintf("ErrorCodes_Args=%s", command))

		output, err := cmd.CombinedOutput()

		e, ok := err.(*exec.ExitError)

		if !ok {
			t.Log("was expecting exit code which did not happen")
			t.FailNow()
		}

		actualOutput := string(output)

		should.BeEqual(expectedErr, e.Error(), assumption)
		should.BeEqual(expectedOutput, actualOutput, assumption)
	}

	assertThat("should exit with code 5 if no args provided", "calc", "exit status 5", "error: invalid syntax\n")
}

func TestMain_ErrorCodes_Inception(t *testing.T) {
	args := os.Getenv("ErrorCodes_Args")
	if args != "" {
		os.Args = strings.Split(args, " ")

		main()
	}
}
