package main

import (
	"os"

	"github.com/pjbgf/go-sample-console-app/cmd/cli"
)

func main() {
	cli.NewConsole(os.Stdout, os.Stderr, os.Exit).Run(os.Args)
}
