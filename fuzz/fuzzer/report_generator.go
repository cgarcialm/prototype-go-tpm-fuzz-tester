package fuzzer

import (
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	// Open the first report (fuzzing report)
	fuzzingReport, err := os.Open("./fuzzer/reports/report_fuzzer.txt")
	if err != nil {
		log.Fatalf("Failed to open fuzzing report: %v", err)
	}
	defer fuzzingReport.Close()

	// Open the second report (fuzzing_with_seeds report)
	fuzzingWithSeedsReport, err := os.Open("./fuzzer/reports/report_custom_inputs.txt")
	if err != nil {
		log.Fatalf("Failed to open fuzzing_with_seeds report: %v", err)
	}
	defer fuzzingWithSeedsReport.Close()

	// Create the consolidated report file
	finalReport, err := os.Create("final_report.txt")
	if err != nil {
		log.Fatalf("Failed to create final report file: %v", err)
	}
	defer finalReport.Close()

	// Write the fuzzing report to the final report
	_, err = io.Copy(finalReport, fuzzingReport)
	if err != nil {
		log.Fatalf("Failed to copy fuzzing report: %v", err)
	}

	// Write the fuzzing_with_seeds report to the final report
	_, err = io.Copy(finalReport, fuzzingWithSeedsReport)
	if err != nil {
		log.Fatalf("Failed to copy fuzzing_with_seeds report: %v", err)
	}

	fmt.Println("Final report generated: final_report.txt")
}
