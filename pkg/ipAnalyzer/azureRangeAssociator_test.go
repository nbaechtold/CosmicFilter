package ipanalyzer

import (
	"testing"
)

func TestAzureRangeAssociator(t *testing.T) {
	associator, err := NewAzureAssociator()
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

	// Check known AWS IPv4
	result, ipRange, err := associator.CheckIp("20.46.15.1")

	if err != nil {
		t.Fatalf("failed to check ip: %v", err)
	}

	if result != true {
		t.Fatalf("ip not found in range")
	}

	if ipRange.Service != "Azure - AzureAPIForFHIR" {
		t.Fatalf("incorrect service name %v", ipRange.Service)
	}

	// Check known AWS IPv6
	result, ipRange, err = associator.CheckIp("2603:1020:305:402::140")

	if err != nil {
		t.Fatalf("failed to check ip: %v", err)
	}

	if result != true {
		t.Fatalf("ip not found in range")
	}

	if ipRange.Service != "Azure - AzureApiManagement" {
		t.Fatalf("incorrect service name %v", ipRange.Service)
	}
}
