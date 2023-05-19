package ipanalyzer

import (
	"testing"
)

func TestCheckPrivateIp(t *testing.T) {
	// Test case 1: Valid IP address
	associator := GetPriateAssociator()

	result, association, err := associator.CheckIp("192.168.1.1")

	if err != nil {
		t.Errorf("Error checking IP: %s", err.Error())
	}

	if !result {
		t.Errorf("Expected IP to be private")
	}

	if association.Service != INTERNAL_IP {
		t.Errorf("Expected service to be %s, got %s", INTERNAL_IP, association.Service)
	}
}

func TestCheckPublicIp(t *testing.T) {
	// Test case 1: Valid IP address
	associator := GetPriateAssociator()

	result, association, err := associator.CheckIp("122.1.1.1")

	if err != nil {
		t.Errorf("Error checking IP: %s", err.Error())
	}

	if result {
		t.Errorf("Expected IP not be private")
	}

	if association.Service != "" {
		t.Errorf("Expected service to be empty, got %s", association.Service)
	}
}
