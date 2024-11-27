package fuzzer

import (
	"fmt"
	"os"
	proto "prototype-go-tpm-fuzz-tester/fuzz/proto" // Import the generated SeedData struct from fuzz/proto

	"google.golang.org/protobuf/encoding/prototext"
)

// ReadSeedData reads the custom prototext seed data from the 'fuzz/seeds' folder.
func ReadSeedData() (*proto.SeedData, error) { // Correctly use the generated SeedData struct from fuzz/proto
	// Define the path to the prototext file in the 'seeds' folder
	path := "../seeds/custom_seeds.prototext"

	// Read the prototext file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read prototext file: %v", err)
	}

	// Parse the prototext data into SeedData
	var seedData proto.SeedData // Correctly use the generated SeedData struct
	err = prototext.Unmarshal(data, &seedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal prototext data: %v", err)
	}

	return &seedData, nil
}
