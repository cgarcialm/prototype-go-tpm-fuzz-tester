// fuzzer_test.go
package fuzzer

import (
	"fmt"
	"io"
	"log"
	"testing"

	"prototype-go-tpm-fuzz-tester/tpmutil"

	. "prototype-go-tpm-fuzz-tester/legacy/tpm2"

	"github.com/google/go-tpm-tools/simulator"
)

// TPMContext holds the state needed during fuzzing.
type TPMContext struct {
	LoadedKeys []tpmutil.Handle
}

// List of commands that the fuzzer can invoke
const (
	TPMGetRandomCmd = iota
	TPMCreatePrimaryCmd
)

func openTPM(tb testing.TB) io.ReadWriteCloser {
	tb.Helper()
	simulator, err := simulator.Get()
	if err != nil {
		tb.Fatalf("Simulator initialization failed: %v", err)
	}
	return simulator
}

func FuzzTPMSequences(f *testing.F) {
	// Seed the corpus with sequences of TPM commands.
	f.Add(TPMCreatePrimaryCmd, TPMGetRandomCmd, 16)
	f.Add(TPMGetRandomCmd, TPMCreatePrimaryCmd, 32)
	f.Add(TPMCreatePrimaryCmd, TPMCreatePrimaryCmd, 16)

	// Define the fuzzing function
	f.Fuzz(func(t *testing.T, cmd1 int, cmd2 int, numBytes int) {
		// Log the commands being tested
		log.Printf("Fuzzing with commands: cmd1=%d, cmd2=%d", cmd1, cmd2)

		cmds := []int{cmd1, cmd2}

		rwc := openTPM(t)
		defer rwc.Close()

		ctx := &TPMContext{}

		for i, cmd := range cmds {
			log.Printf("Executing command %d: %d", i, cmd)
			switch cmd {
			case TPMCreatePrimaryCmd:
				err := TPMCreatePrimary(rwc, ctx)
				if err != nil {
					t.Errorf("Failed to create TPM object at command %d: %v", i, err)
					return
				}
				log.Printf("Successfully created TPM primary key at command %d", i)

			case TPMGetRandomCmd:
				err := TPMGetRandom(rwc, numBytes)
				if err != nil {
					t.Errorf("Failed to get random bytes at command %d: %v", i, err)
					return
				}
				log.Printf("Successfully obtained random bytes at command %d", i)

			default:
				log.Printf("Skipping unknown command %d: %d", i, cmd)
				t.Skip("Unknown command")
			}
		}
	})
}

// TPMGetRandom simulates getting random bytes from the TPM.
func TPMGetRandom(rwc io.ReadWriteCloser, numBytes int) error {
	// Convert numBytes to uint16 for GetRandom
	_, err := GetRandom(rwc, uint16(numBytes))
	if err != nil {
		return fmt.Errorf("GetRandom failed: %v", err)
	}
	return nil
}

var (
	emptyPassword    = ""
	defaultPassword  = "\x01\x02\x03\x04"
	pcrSelection7    = PCRSelection{Hash: AlgSHA1, PCRs: []int{7}}
	defaultKeyParams = Public{
		Type:       AlgRSA,
		NameAlg:    AlgSHA1,
		Attributes: FlagStorageDefault,
		RSAParameters: &RSAParams{
			Symmetric: &SymScheme{
				Alg:     AlgAES,
				KeyBits: 128,
				Mode:    AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 1<<16 + 1,
		},
	}
)

// TPMCreatePrimary creates a primary key in the TPM.
func TPMCreatePrimary(rwc io.ReadWriteCloser, ctx *TPMContext) error {
	// Create the primary key using the simplest approach possible
	parentHandle, _, err := CreatePrimary(rwc, HandleOwner, pcrSelection7, emptyPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		return fmt.Errorf("CreatePrimary failed: %v", err)
	}
	defer FlushContext(rwc, parentHandle)

	log.Printf("Created primary key with handle: %v", parentHandle)

	// Add the created handle to the context for future use
	ctx.LoadedKeys = append(ctx.LoadedKeys, tpmutil.Handle(parentHandle))
	return nil
}
