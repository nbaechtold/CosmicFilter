package ipanalyzer

import (
	"encoding/json"
	"net"
	"net/http"
)

type GithubMeta struct {
	VerifiablePasswordAuthentication bool     `json:"verifiable_password_authentication"`
	Git                              []string `json:"git"`
	Hooks                            []string `json:"hooks"`
	Pages                            []string `json:"pages"`
	Api                              []string `json:"api"`
	Web                              []string `json:"web"`
	Packages                         []string `json:"packages"`
	Importer                         []string `json:"importer"`
	Dependabot                       []string `json:"dependabot"`
	Actions                          []string `json:"actions"`
}

func retrieveGithubRanges() (*GithubMeta, error) {
	resp, err := http.Get("https://api.github.com/meta")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var githubMeta GithubMeta
	err = json.NewDecoder(resp.Body).Decode(&githubMeta)
	if err != nil {
		return nil, err
	}

	return &githubMeta, nil
}

// GetGithubRanges returns a slice of IPRange structs containing the IP ranges from a GithubMeta struct
func NewGitHubAssociator() (*CidrServiceAssociator, error) {
	githubMeta, err := retrieveGithubRanges()
	if err != nil {
		return &CidrServiceAssociator{}, err
	}

	var ranges []IpRangeAssociation
	for _, prefix := range githubMeta.Hooks {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "hooks", AssociationType: SERVICE})
	}

	for _, prefix := range githubMeta.Git {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "git", AssociationType: SERVICE})
	}

	for _, prefix := range githubMeta.Pages {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "pages", AssociationType: SERVICE})
	}

	for _, prefix := range githubMeta.Api {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "api", AssociationType: SERVICE})
	}

	for _, prefix := range githubMeta.Web {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "web", AssociationType: SERVICE})
	}

	for _, prefix := range githubMeta.Packages {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "packages", AssociationType: SERVICE})
	}

	for _, prefix := range githubMeta.Importer {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "importer", AssociationType: SERVICE})
	}

	for _, prefix := range githubMeta.Dependabot {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "dependabot", AssociationType: SERVICE})
	}

	for _, prefix := range githubMeta.Actions {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			return &CidrServiceAssociator{}, err
		}
		ranges = append(ranges, IpRangeAssociation{Range: *ipNet, Service: "github", Location: "actions", AssociationType: SERVICE})
	}

	return &CidrServiceAssociator{ipRanges: ranges}, nil
}
