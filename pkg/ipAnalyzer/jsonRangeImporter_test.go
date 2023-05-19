package ipanalyzer

import (
	"os"
	"testing"
)

func TestNewJsonRangeAssociator(t *testing.T) {
	file, err := os.Open("../../test/jsonRanges/format.json")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer file.Close()

	ranges, err := NewJsonRangeAssociator(file)
	if err != nil {
		t.Fatalf("failed to create range associator: %v", err)
	}

	result, ipRange, err := ranges.CheckIp("10.1.1.1")

	if err != nil {
		t.Fatalf("failed to check ip: %v", err)
	}

	if result != true {
		t.Fatalf("ip not found in range")
	}

	if ipRange.Service != "service2" {
		t.Fatalf("incorrect service name")
	}

	if ipRange.Location != "us-east-2" {
		t.Fatalf("incorrect location")
	}
}
