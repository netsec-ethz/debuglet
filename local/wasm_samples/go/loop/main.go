package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	print = flag.Bool("print", false, "if the loop should print to stdout")
	limit = flag.Int("limit", 0, "if > 0, the loop will exit after this many iterations")
)

// Simple infinite loop with no IO to test timing out debuglets
func main() {
	flag.CommandLine.Parse(os.Args)

	c := 0
	for c < *limit || *limit == 0 {
		if *print && c%1_000_000 == 0 {
			fmt.Println("looping", c)
		}
		c++
	}
}
