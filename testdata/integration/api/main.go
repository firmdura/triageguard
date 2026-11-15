// This test consumer deliberately imports only the public package.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/firmdura/triageguard/pkg/triageguard"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fatal(err)
	}
	m, err := triageguard.LoadManifest(f)
	closeErr := f.Close()
	if err != nil {
		fatal(err)
	}
	if closeErr != nil {
		fatal(closeErr)
	}
	report, err := triageguard.Check(context.Background(), m, os.Args[2])
	if err != nil {
		fatal(err)
	}
	if err := triageguard.WriteJSON(os.Stdout, report); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
