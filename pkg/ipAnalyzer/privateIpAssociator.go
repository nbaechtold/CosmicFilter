package ipanalyzer

import (
	"fmt"
	"net"
)

type PrivateIpAssociator struct {
}

func GetPriateAssociator() *PrivateIpAssociator {
	return &PrivateIpAssociator{}
}

// CheckIp checks if the given IP is internal or public
func (pia *PrivateIpAssociator) CheckIp(ip string) (bool, IpRangeAssociation, error) {
	checkIp := net.ParseIP(ip)
	if checkIp == nil {
		return false, IpRangeAssociation{}, fmt.Errorf("invalid IP: %s", ip)
	}

	if checkIp.IsPrivate() {
		return true, IpRangeAssociation{
			Range:           net.IPNet{IP: checkIp, Mask: net.CIDRMask(32, 32)},
			Service:         INTERNAL_IP,
			Location:        INTERNAL_IP,
			AssociationType: INTERNAL_IP,
		}, nil
	}

	return false, IpRangeAssociation{}, nil
}
