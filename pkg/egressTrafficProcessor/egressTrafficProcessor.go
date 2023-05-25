package egresstrafficprocessor

import (
	"encoding/csv"
	"fmt"
	"io"

	"github.com/cornelk/hashmap"
	ipanalyzer "github.com/nbaechtold/CosmicFilter/pkg/ipAnalyzer"
)

type EgressAssociations struct {
	Primary   ipanalyzer.IpRangeAssociation
	Secondary []ipanalyzer.IpRangeAssociation
}

type EgressTrafficProcessor struct {
	LookupCache *hashmap.Map[string, EgressAssociations]
	Associators []ipanalyzer.IPRangeAssociator
}

// GetEgressTrafficProcessor
func GetEgressTrafficProcessor(jsonDocuments []io.Reader) (*EgressTrafficProcessor, error) {

	// Load up all of our associators
	var egressProcessor EgressTrafficProcessor

	// Initialize hashmap for lookup cache
	egressProcessor.LookupCache = hashmap.New[string, EgressAssociations]()

	// Add JSON associators
	for _, jsonDocument := range jsonDocuments {
		associator, err := ipanalyzer.NewJsonRangeAssociator(jsonDocument)
		if err != nil {
			return nil, err
		}
		egressProcessor.Associators = append(egressProcessor.Associators, associator)
	}

	// Add GitHub assocator
	githubAssociator, err := ipanalyzer.NewGitHubAssociator()
	if err != nil {
		return nil, err
	}
	egressProcessor.Associators = append(egressProcessor.Associators, githubAssociator)

	// Add Private IP associator
	egressProcessor.Associators = append(egressProcessor.Associators, ipanalyzer.GetPriateAssociator())

	// Add GCP associator
	gcpAssociator, err := ipanalyzer.NewGCPAssociator()
	if err != nil {
		return nil, err
	}
	egressProcessor.Associators = append(egressProcessor.Associators, gcpAssociator)

	// Add Google associator
	googleAssociator, err := ipanalyzer.NewGoogleAssociator()
	if err != nil {
		return nil, err
	}
	egressProcessor.Associators = append(egressProcessor.Associators, googleAssociator)

	// Add AWS Assocaitor
	awsAssociator, err := ipanalyzer.NewAWSAssociator()
	if err != nil {
		return nil, err
	}
	egressProcessor.Associators = append(egressProcessor.Associators, awsAssociator)

	// Add Azure associator
	azureAssociator, err := ipanalyzer.NewAzureAssociator()
	if err != nil {
		return nil, err
	}
	egressProcessor.Associators = append(egressProcessor.Associators, azureAssociator)

	// Add DNS associator
	egressProcessor.Associators = append(egressProcessor.Associators, ipanalyzer.NewDNSAssociator())

	return &egressProcessor, nil

}

func (esp *EgressTrafficProcessor) ProcessCSV(reader io.Reader, writer io.Writer, ipIndex int) error {
	r := csv.NewReader(reader)
	w := csv.NewWriter(writer)

	ch := make(chan []string)

	recordCount := 0

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		recordCount++
		go func() {
			if len(record) <= ipIndex {
				ch <- record
				return
			}

			association, err := esp.processEgressRecord(record[ipIndex])

			if err != nil {
				record = append(record, err.Error())
				ch <- record
				return
			}

			record = append(record, association.Primary.Service)
			for _, secondaryAssociation := range association.Secondary {
				record = append(record, secondaryAssociation.Service)
			}
			ch <- record
		}()
	}

	for i := 0; i < recordCount; i++ {
		record := <-ch
		w.Write(record)
		// Flush every 100 lines to disk
		if i%100 == 0 {
			fmt.Printf("Processed record: %v/%v\n", i, recordCount)
			w.Flush()
		}
	}
	w.Flush()
	return nil
}

func (erp *EgressTrafficProcessor) processEgressRecord(ipAddress string) (EgressAssociations, error) {
	// Check cache for IP address
	if cacheAssociations, ok := erp.LookupCache.Get(ipAddress); ok {
		return cacheAssociations, nil
	}

	var associations []ipanalyzer.IpRangeAssociation

	// Check each associator for the IP address
	for _, associator := range erp.Associators {
		result, ipRange, err := associator.CheckIp(ipAddress)
		if err != nil {
			return EgressAssociations{}, err
		}
		if result {
			associations = append(associations, ipRange)
		}
	}

	// Find the best association for primary association
	primaryIndex := findBestAssociationIndex(associations)
	var egressAssociation EgressAssociations

	for i, association := range associations {
		if i == primaryIndex {
			egressAssociation.Primary = association
		} else {
			egressAssociation.Secondary = append(egressAssociation.Secondary, association)
		}
	}

	// Add to cache
	erp.LookupCache.Set(ipAddress, egressAssociation)

	return egressAssociation, nil
}

// findBestAssociationIndex finds the best association for primary association
func findBestAssociationIndex(associations []ipanalyzer.IpRangeAssociation) int {
	var bestAssociationIndex int
	var bestAssociationType string

	for i, association := range associations {
		if getAssociationTypeRanking(association.AssociationType) > getAssociationTypeRanking(bestAssociationType) {
			bestAssociationIndex = i
			bestAssociationType = association.AssociationType
		}
	}

	return bestAssociationIndex
}

func getAssociationTypeRanking(associationType string) int {
	// Find the best association for primary association
	// Order of preference is
	// 1. SERVICE
	// 2. INTERNAL_IP
	// 3. DNS
	// 4. CLOUD_PROVDER
	switch associationType {
	case ipanalyzer.SERVICE:
		return 1
	case ipanalyzer.INTERNAL_IP:
		return 2
	case ipanalyzer.DNS:
		return 3
	case ipanalyzer.CLOUD_PROVDER:
		return 4
	default:
		return 5
	}
}
