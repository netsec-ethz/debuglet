package main

import (
	"flag"
	"os"
)

var (
	print = flag.Bool("print", false, "if the loop should print to stdout")
)

// Simple infinite loop with no IO to test timing out debuglets
func main() {
	flag.CommandLine.Parse(os.Args)

	c := 0
	for {
		if *print && c%1000000 == 0 {
			println("looping", c)
		}
		c++
	}
}
