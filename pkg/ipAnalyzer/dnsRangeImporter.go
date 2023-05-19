package ipanalyzer

import (
	"net"
	"strings"

	"github.com/cornelk/hashmap"
)

type DNSAssociator struct {
	dnsCache *hashmap.Map[string, []string]
}

func NewDNSAssociator() *DNSAssociator {
	return &DNSAssociator{
		dnsCache: hashmap.New[string, []string](),
	}
}

// CheckIp returns the DNS name of the IP if it exists
func (a *DNSAssociator) CheckIp(ip string) (bool, IpRangeAssociation, error) {
	// Check if IP is in cache
	if service, ok := a.dnsCache.Get(ip); ok {
		// No DNS records found
		if len(service) == 0 {
			return false, IpRangeAssociation{}, nil
		}

		// Return cached result
		return true,
			IpRangeAssociation{
				Range:           net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(32, 32)},
				Service:         strings.Join(service, ", "),
				AssociationType: DNS,
			},
			nil
	}

	// Perform reverse DNS lookup on IP
	names, err := net.LookupAddr(ip)
	if err != nil {
		// Cache empty result
		a.dnsCache.Set(ip, []string{})

		// Diffiult to tell whether error is due to NXDOMAIN or other error so handle error here
		return false, IpRangeAssociation{}, nil
	}

	// Cache result
	a.dnsCache.Set(ip, names)

	// Return IpRange with the service name
	return true, IpRangeAssociation{
		Range:           net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(32, 32)},
		Service:         strings.Join(names, ", "),
		AssociationType: DNS,
	}, nil
}
