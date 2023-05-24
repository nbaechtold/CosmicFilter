package ipanalyzer

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

type GcpCloudIPRanges struct {
	SyncToken  string      `json:"syncToken"`
	CreateDate string      `json:"createDate"`
	Prefixes   []GcpPrefix `json:"prefixes"`
}

type GcpPrefix struct {
	IPv4Prefix string `json:"ipv4Prefix"`
	IPv6Prefix string `json:"ipv6Prefix"`
	Service    string `json:"service"`
	Scope      string `json:"scope"`
}

type Prefixes struct {
}

func retrieveGCPRanges() (*GcpCloudIPRanges, error) {
	resp, err := http.Get("https://www.gstatic.com/ipranges/cloud.json")
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()

	var cloudIPRanges GcpCloudIPRanges
	err = json.NewDecoder(resp.Body).Decode(&cloudIPRanges)
	if err != nil {
		fmt.Println("Error decoding JSON response:", err)
		return nil, err
	}

	return &cloudIPRanges, nil
}

// GetGCPRanges returns a slice of IPRange structs containing the IP ranges from a CloudIPRanges struct
func NewGCPAssociator() (*CidrServiceAssociator, error) {
	cloudIPRanges, err := retrieveGCPRanges()
	if err != nil {
		return &CidrServiceAssociator{}, err
	}

	var ranges []IpRangeAssociation
	for _, prefix := range cloudIPRanges.Prefixes {

		cidrRange := prefix.IPv4Prefix
		// Use IPv6 if IPv4 is empty
		if cidrRange == "" {
			cidrRange = prefix.IPv6Prefix
		}
		_, ipNet, err := net.ParseCIDR(cidrRange)
		if err != nil {
			fmt.Println("Error parsing CIDR:", err)
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: prefix.Service, Location: prefix.Scope, AssociationType: CLOUD_PROVDER})
	}

	return &CidrServiceAssociator{ipRanges: ranges}, nil
}
