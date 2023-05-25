package ipanalyzer

import (
	"encoding/json"
	"net"
	"net/http"
)

type AzureIpRangesSource struct {
	ChangeNumber int64               `json:"changeNumber"`
	Cloud        string              `json:"cloud"`
	Values       []AzureIpRangeValue `json:"values"`
}

type AzureIpRangeValue struct {
	Name       string                 `json:"name"`
	ID         string                 `json:"id"`
	Properties AzureIpRangeProperties `json:"properties"`
}

type AzureIpRangeProperties struct {
	ChangeNumber    int64    `json:"changeNumber"`
	Region          string   `json:"region"`
	RegionID        int64    `json:"regionId"`
	Platform        string   `json:"platform"`
	SystemService   string   `json:"systemService"`
	AddressPrefixes []string `json:"addressPrefixes"`
	NetworkFeatures []string `json:"networkFeatures"`
}

func getAzureIpRanges() (*AzureIpRangesSource, error) {
	url := "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230522.json"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ipRanges AzureIpRangesSource
	err = json.NewDecoder(resp.Body).Decode(&ipRanges)
	if err != nil {
		return nil, err
	}

	return &ipRanges, nil
}

func NewAzureAssociator() (*CidrServiceAssociator, error) {
	ranges, err := getAzureIpRanges()

	if err != nil {
		return nil, err
	}

	var ipRanges []IpRangeAssociation
	for _, value := range ranges.Values {
		for _, cidrRange := range value.Properties.AddressPrefixes {
			_, ipNet, err := net.ParseCIDR(cidrRange)
			if err != nil {
				return nil, err
			}
			ipRanges = append(ipRanges, IpRangeAssociation{
				Range:   *ipNet,
				Service: value.Properties.Platform + " - " + value.Properties.SystemService,
			})
		}
	}

	return &CidrServiceAssociator{
		ipRanges: ipRanges,
	}, nil

}
