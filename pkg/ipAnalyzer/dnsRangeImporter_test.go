package ipanalyzer

import (
	"reflect"
	"testing"
)

func TestDNSCheckIP(t *testing.T) {
	dnsAssociator := NewDNSAssociator()

	result, ipRange, err := dnsAssociator.CheckIp("23.205.156.162")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !result {
		t.Errorf("Expected true result")
	}

	if ipRange.Service == "" {
		t.Errorf("Expected a service name, got %v", ipRange.Service)
	}

	// Check Cache
	resultCache, ipRangeCache, errCache := dnsAssociator.CheckIp("23.205.156.162")

	if errCache != err {
		t.Errorf("Unexpected error: %v", errCache)
	}

	if resultCache != result {
		t.Errorf("Differnt result from cache")
	}

	if !reflect.DeepEqual(ipRangeCache, ipRange) {
		t.Errorf("Differnt ipRange from cache")
	}

	result, ipRange, err = dnsAssociator.CheckIp("1.20.1.2")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result {
		t.Errorf("Expected false result")
	}
}
