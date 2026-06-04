package main

import (
	"fmt"
	"os"

	vt "github.com/VirusTotal/vt-go"
)

func virusTotal(sha256 *string) (any, error) {
	virusapikey := os.Getenv("VIRUS_API_KEY")

	if virusapikey == "" {
		return nil, fmt.Errorf("VIRUS_API_KEY not configured")
	}

	if *sha256 == "" {
		return nil, fmt.Errorf("empty sha256")
	}

	client := vt.NewClient(virusapikey)

	file, err := client.GetObject(vt.URL("files/%s", *sha256))
	if err != nil {
		return map[string]any{
			"found":   false,
			"message": err.Error(),
		}, nil
	}

	ls, err := file.GetTime("last_submission_date")
	if err != nil {
		return nil, err
	}

	fmt.Printf("File %s was submitted for the last time on %v\n", file.ID(), ls)
	results, err := file.Get("last_analysis_stats")
	if err != nil {
		return nil, err
	}

	return results, nil
}
