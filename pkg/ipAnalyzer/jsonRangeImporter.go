package ipanalyzer

import (
	"encoding/json"
	"io"
	"net"
)

type Service struct {
	Name       string   `json:"name"`
	Location   string   `json:"location"`
	CidrRanges []string `json:"CidrRanges"`
}

type JsonServiceList struct {
	Services []Service `json:"services"`
}

func NewJsonRangeAssociator(r io.Reader) (*CidrServiceAssociator, error) {
	var serviceList JsonServiceList
	err := json.NewDecoder(r).Decode(&serviceList)
	if err != nil {
		return nil, err
	}

	var ipRanges []IpRangeAssociation

	// Iterate over the services and convert them to a CidrServiceAssociator
	for _, service := range serviceList.Services {
		// Convert the CidrRanges to IPRange structs

		for _, cidrRange := range service.CidrRanges {
			_, ipNet, err := net.ParseCIDR(cidrRange)
			if err != nil {
				return nil, err
			}
			ipRange := IpRangeAssociation{
				Range:           *ipNet,
				Service:         service.Name,
				Location:        service.Location,
				AssociationType: SERVICE,
			}
			ipRanges = append(ipRanges, ipRange)
		}
	}

	return &CidrServiceAssociator{ipRanges: ipRanges}, nil
}
