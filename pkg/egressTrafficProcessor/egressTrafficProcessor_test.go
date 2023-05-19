package egresstrafficprocessor

import (
	"io"
	"os"
	"testing"
)

func TestGetEgressTrafficProcessor(t *testing.T) {
	jsonFile, err := os.Open("../../test/jsonRanges/format.json")
	defer jsonFile.Close()

	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}

	csvOutput, err := os.Create("../../test/csv/output.csv")
	defer csvOutput.Close()

	if err != nil {
		t.Fatalf("failed to create csv output file: %v", err)
	}

	csvInput, err := os.Open("../../test/csv/data copy.csv")
	defer csvInput.Close()

	if err != nil {
		t.Fatalf("failed to open csv input file: %v", err)
	}

	egressProcessor, err := GetEgressTrafficProcessor([]io.Reader{jsonFile})
	if err != nil {
		t.Fatalf("failed to create egress traffic processor: %v", err)
	}

	err = egressProcessor.ProcessCSV(csvInput, csvOutput, 1)

	if err != nil {
		t.Fatalf("failed to process csv: %v", err)
	}
}
