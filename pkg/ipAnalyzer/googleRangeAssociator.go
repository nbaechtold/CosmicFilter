package ipanalyzer

import (
	"encoding/json"
	"net"
	"net/http"
)

type CidrRange struct {
	IPV4Prefix string `json:"ipv4Prefix"`
	IPV6Prefix string `json:"ipv6Prefix"`
}

type GoogleIPRanges struct {
	SyncToken    string      `json:"syncToken"`
	CreationTime string      `json:"creationTime"`
	Prefixes     []CidrRange `json:"prefixes"`
}

func NewGoogleAssociator() (*CidrServiceAssociator, error) {
	resp, err := http.Get("https://www.gstatic.com/ipranges/goog.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ranges GoogleIPRanges
	err = json.NewDecoder(resp.Body).Decode(&ranges)
	if err != nil {
		return nil, err
	}

	var associations []IpRangeAssociation
	for _, prefix := range ranges.Prefixes {
		cidrRange := prefix.IPV4Prefix
		if cidrRange == "" {
			cidrRange = prefix.IPV6Prefix
		}
		_, ipNet, err := net.ParseCIDR(cidrRange)
		if err != nil {
			return nil, err
		}
		associations = append(associations, IpRangeAssociation{
			Range:   *ipNet,
			Service: "Google General",
		})
	}

	return &CidrServiceAssociator{
		ipRanges: associations,
	}, nil
}
