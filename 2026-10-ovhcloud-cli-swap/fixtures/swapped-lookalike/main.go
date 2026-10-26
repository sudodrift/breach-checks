// A harmless program used only as a test fixture. It has no stealer code.
// It carries the commit id of the swapped OVHcloud build as a plain string and
// is built with -ldflags="-s -w", so it has the same two fingerprints that
// check.sh looks for. It is never executed by the tests.
package main

var commit = "5ead8ef9b43d354dfb5caadff803b11afc8c5c58"

func main() { println(commit) }
