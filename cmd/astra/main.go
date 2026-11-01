package main

import (
	"fmt"
	"os"

	"github.com/astra-ai/astra/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "astra:", err)
		os.Exit(1)
	}
}
