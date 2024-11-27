package main

import (
	"fmt"
	"log"
	"prototype-go-tpm-fuzz-tester/fuzz/fuzzer" // Import the fuzzer package
)

func main() {
	// Call the GenerateReport function from the fuzzer package
	if err := fuzzer.GenerateReport(); err != nil {
		log.Fatalf("Error generating report: %v", err)
	}

	fmt.Println("Report generation completed successfully.")
}
