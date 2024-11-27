package fuzzer

import (
	"fmt"
	"io"
	"os"
)

// GenerateReport consolidates multiple fuzzing reports into a final one.
func GenerateReport() error {
	// Open the first report (fuzzing report)
	fuzzingReport, err := os.Open("./fuzz/reports/report_fuzzer.txt")
	if err != nil {
		return fmt.Errorf("failed to open fuzzing report: %v", err)
	}
	defer fuzzingReport.Close()

	// Open the second report (fuzzing_with_seeds report)
	fuzzingWithSeedsReport, err := os.Open("./fuzz/reports/report_custom_inputs.txt")
	if err != nil {
		return fmt.Errorf("failed to open fuzzing_with_seeds report: %v", err)
	}
	defer fuzzingWithSeedsReport.Close()

	// Create the consolidated final report file
	finalReport, err := os.Create("final_report.txt")
	if err != nil {
		return fmt.Errorf("failed to create final report file: %v", err)
	}
	defer finalReport.Close()

	// Write the fuzzing report to the final report
	_, err = io.Copy(finalReport, fuzzingReport)
	if err != nil {
		return fmt.Errorf("failed to copy fuzzing report: %v", err)
	}

	// Write the fuzzing_with_seeds report to the final report
	_, err = io.Copy(finalReport, fuzzingWithSeedsReport)
	if err != nil {
		return fmt.Errorf("failed to copy fuzzing_with_seeds report: %v", err)
	}

	fmt.Println("Final report generated: final_report.txt")
	return nil
}
