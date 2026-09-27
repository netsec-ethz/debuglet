package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Hello from Debuglet!")
	// The host passes debuglet arguments directly, without a program-name entry.
	for _, arg := range os.Args {
		fmt.Println(arg)
	}
}
