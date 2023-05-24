package ipanalyzer

import (
	"testing"
)

func TestGoogleRangeAssociator(t *testing.T) {
	associator, err := NewGoogleAssociator()
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

	// Check known Google IP
	result, ipRange, err := associator.CheckIp("34.3.0.1")

	if err != nil {
		t.Fatalf("failed to check ip: %v", err)
	}

	if result != true {
		t.Fatalf("ip not found in range")
	}

	if ipRange.Service != "Google General" {
		t.Fatalf("incorrect service name")
	}
}
