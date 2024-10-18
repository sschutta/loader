// Loader reads an executable file and prints its section and symbol data.
package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/sschutta/loader"
)

func main() {
	fname := os.Args[1]

	bin := new(loader.Binary)
	if err := loader.LoadBinary(fname, bin, loader.BIN_TYPE_AUTO); err != nil {
		fmt.Printf("could not load binary: %v\n", err)
		return
	}
	defer loader.UnloadBinary(bin)

	fmt.Printf("loaded binary %s\n", bin)

	// we use a tabwriter so that the sections and symbols print out nicely; the
	// book's C approach doesn't work as well here
	w := tabwriter.NewWriter(os.Stdout, 0, 1, 1, ' ', tabwriter.TabIndent)

	for _, section := range bin.Sections {
		fmt.Fprintf(w, "%s\n", section)
	}
	w.Flush()

	if len(bin.Symbols) > 0 {
		fmt.Println("scanned symbol tables")
	}

	for _, symbol := range bin.Symbols {
		fmt.Fprintf(w, "%s\n", symbol)
	}
	w.Flush()
}
