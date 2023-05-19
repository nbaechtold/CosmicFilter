package ipanalyzer

import (
	"testing"
)

func TestGcpRangeAssociator(t *testing.T) {
	associator, err := NewGCPAssociator()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(associator.ipRanges) == 0 {
		t.Errorf("Expected non-empty ranges")
	}

	for _, r := range associator.ipRanges {
		if r.Range.IP == nil {
			t.Errorf("Expected non-nil IP in range %v", r)
		}
		if r.Range.Mask == nil {
			t.Errorf("Expected non-nil Mask in range %v", r)
		}
		if r.Service == "" {
			t.Errorf("Expected non-empty Service in range %v", r)
		}
	}

	// Check known GCP IP
	result, ipRange, err := associator.CheckIp("34.21.0.1")

	if err != nil {
		t.Fatalf("failed to check ip: %v", err)
	}

	if result != true {
		t.Fatalf("ip not found in range")
	}

	if ipRange.Service != "Google Cloud" {
		t.Fatalf("incorrect service name")
	}

	if ipRange.Location != "us-east4" {
		t.Fatalf("incorrect location")
	}
}
