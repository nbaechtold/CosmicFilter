/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"io"
	"os"

	egresstrafficprocessor "github.com/nbaechtold/CosmicFilter/pkg/egressTrafficProcessor"
	"github.com/spf13/cobra"
)

// analyzeCmd represents the analyze command
var analyzeCmd = &cobra.Command{
	Use:   "analyzeCSV",
	Short: "Will produce a new CSV file with an additional column containing the information for the destination of the egress traffic",
	Long: `This utility takes a CSV file with a column of IP addresses and outputs a CSV file with the same data, 
	but with an additional column containing the destination of the egress traffic.
	The first additional column will contain the best guess for the destination of the egress traffic.
	The following columns will contain extra information that could be useful such as whether the address
	was from a cloud provider.`,

	Run: func(cmd *cobra.Command, args []string) {

		fmt.Printf("Analyzing IPs in file: %s\n", cmd.Flag("input").Value)
		jsonMapping := []io.Reader{}

		if associationFile, _ := cmd.Flags().GetString("addressAssociations"); associationFile != "" {
			jsonFile, err := os.Open(associationFile)

			if err != nil {
				fmt.Printf("Failed to open file: %v", err)
				os.Exit(1)
			}
			defer jsonFile.Close()
			jsonMapping = append(jsonMapping, jsonFile)

		}

		egressProcessor, err := egresstrafficprocessor.GetEgressTrafficProcessor(jsonMapping)

		if err != nil {
			fmt.Printf("Failed to create egress traffic processor: %v", err)
			os.Exit(1)
		}

		sourceCSVPath, _ := cmd.Flags().GetString("input")
		sourceCSV, err := os.Open(sourceCSVPath)
		if err != nil {
			fmt.Printf("Failed to open file: %v", err)
			os.Exit(1)
		}

		outputCSVPath, _ := cmd.Flags().GetString("output")
		outputCSV, err := os.Create(outputCSVPath)

		if err != nil {
			fmt.Printf("Failed to create output file: %v", err)
			os.Exit(1)
		}

		defer outputCSV.Close()

		ipColumn, _ := cmd.Flags().GetInt("ipColumn")

		err = egressProcessor.ProcessCSV(sourceCSV, outputCSV, ipColumn)

		if err != nil {
			fmt.Printf("Failed to process CSV: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// analyzeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// analyzeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	analyzeCmd.Flags().StringP("input", "i", "", "Input CSV file to process")
	analyzeCmd.MarkFlagRequired("input")
	analyzeCmd.Flags().StringP("output", "o", "", "Output CSV file to write to")
	analyzeCmd.MarkFlagRequired("output")
	analyzeCmd.Flags().IntP("ipColumn", "c", 0, "Column number of IP address")
	analyzeCmd.MarkFlagRequired("ipColumn")
	analyzeCmd.Flags().StringP("addressAssociations", "a", "", "Location of json file containing IP address associations")
}
