package ipanalyzer

import (
	"encoding/json"
	"net"
	"net/http"
)

type AWSIPRanges struct {
	SyncToken    string          `json:"syncToken"`
	CreateDate   string          `json:"createDate"`
	Prefixes     []AwsIpPrefix   `json:"prefixes"`
	IPv6Prefixes []AwsIPv6Prefix `json:"ipv6_prefixes"`
}

type AwsIpPrefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type AwsIPv6Prefix struct {
	IPv6Prefix string `json:"ipv6_prefix"`
	Region     string `json:"region"`
	Service    string `json:"service"`
}

func getAWSIPRanges() (*AWSIPRanges, error) {
	url := "https://ip-ranges.amazonaws.com/ip-ranges.json"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ipRanges AWSIPRanges
	err = json.NewDecoder(resp.Body).Decode(&ipRanges)
	if err != nil {
		return nil, err
	}

	return &ipRanges, nil
}

func NewAWSAssociator() (*CidrServiceAssociator, error) {
	ranges, err := getAWSIPRanges()

	if err != nil {
		return nil, err
	}

	var ipRanges []IpRangeAssociation
	for _, prefix := range ranges.Prefixes {
		cidrRange := prefix.IPPrefix
		_, ipNet, err := net.ParseCIDR(cidrRange)
		if err != nil {
			return nil, err
		}

		ipRanges = append(ipRanges, IpRangeAssociation{
			Range:    *ipNet,
			Service:  "AWS - " + prefix.Service,
			Location: prefix.Region,
		})
	}

	for _, prefix := range ranges.IPv6Prefixes {
		cidrRange := prefix.IPv6Prefix
		_, ipNet, err := net.ParseCIDR(cidrRange)
		if err != nil {
			return nil, err
		}

		ipRanges = append(ipRanges, IpRangeAssociation{
			Range:    *ipNet,
			Service:  "AWS - " + prefix.Service,
			Location: prefix.Region,
		})
	}

	return &CidrServiceAssociator{
		ipRanges: ipRanges,
	}, nil

}
