package main

import (
	"fmt"
	"os"

	"github.com/stuart-schutta-dev/loader"
)

func main() {
	fmt.Println("it compiles")
	fname := os.Args[1]
	bin := new(loader.Binary)
	if err := loader.LoadBinary(fname, bin, loader.BIN_TYPE_AUTO); err != nil {
		fmt.Printf("could not load binary: %v\n", err)
		return
	}
	fmt.Printf("%#v\n", bin)
}
