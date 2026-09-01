// Probe: can mvdan.cc/sh parse each line of the shared corpus?
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		name, cmd, _ := strings.Cut(sc.Text(), "\t")
		if _, err := syntax.NewParser().Parse(strings.NewReader(cmd), ""); err != nil {
			fmt.Printf("FAIL  %-24s %v\n", name, err)
			continue
		}
		fmt.Printf("OK    %-24s\n", name)
	}
}
