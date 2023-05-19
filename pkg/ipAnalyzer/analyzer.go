package ipanalyzer

import (
	"fmt"
	"net"
)

type IPRangeAssociator interface {
	CheckIp(ip string) (bool, IpRangeAssociation, error)
}

const (
	CLOUD_PROVDER = "Cloud Provder"
	SERVICE       = "Service"
	INTERNAL_IP   = "Internal IP"
	DNS           = "DNS Lookup"
)

type CidrServiceAssociator struct {
	ipRanges []IpRangeAssociation
}

type IpRangeAssociation struct {
	Range           net.IPNet
	Service         string
	Location        string
	AssociationType string
}

// CheckIp checks if the given IP is in the list of IP ranges for an associator
func (sa *CidrServiceAssociator) CheckIp(ip string) (bool, IpRangeAssociation, error) {
	checkIp := net.ParseIP(ip)
	if checkIp == nil {
		return false, IpRangeAssociation{}, fmt.Errorf("invalid IP: %s", ip)
	}

	for _, r := range sa.ipRanges {
		if r.Range.Contains(checkIp) {
			return true, r, nil
		}
	}

	return false, IpRangeAssociation{}, nil
}
