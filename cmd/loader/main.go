package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/stuart-schutta-dev/loader"
)

func main() {
	fname := os.Args[1]
	bin := new(loader.Binary)
	if err := loader.LoadBinary(fname, bin, loader.BIN_TYPE_AUTO); err != nil {
		fmt.Printf("could not load binary: %v\n", err)
		return
	}
	defer loader.UnloadBinary(bin)

	fmt.Printf("loaded binary %q %s/%s (%d bits) entry@%#016x\n", bin.Filename, bin.TypeStr, bin.ArchStr, bin.Bits, bin.Entry)

	w := tabwriter.NewWriter(os.Stdout, 0, 1, 1, ' ', tabwriter.TabIndent)
	for _, section := range bin.Sections {
		fmt.Fprintf(w, "\t%#016x\t%-8d\t%-20s\t%s\t\n", section.Vma, section.Size, section.Name, section.Type)
	}
	w.Flush()

	if len(bin.Symbols) > 0 {
		fmt.Println("scanned symbol tables")
	}

	w = tabwriter.NewWriter(os.Stdout, 0, 1, 1, ' ', tabwriter.TabIndent)
	for _, symbol := range bin.Symbols {
		fmt.Fprintf(w, "\t%-40s\t%#016x\t%s\t\n", symbol.Name, symbol.Addr, symbol.Type)
	}
	w.Flush()
}
