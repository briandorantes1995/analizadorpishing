package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	vt "github.com/VirusTotal/vt-go"
	"github.com/jhillyerd/enmime"
)

func virusTotal(sha256 *string) (VirusTotalResult, error) {
	virusapikey := os.Getenv("VIRUS_API_KEY")

	if virusapikey == "" {
		return VirusTotalResult{}, fmt.Errorf("VIRUS_API_KEY not configured")
	}

	if *sha256 == "" {
		return VirusTotalResult{}, fmt.Errorf("empty sha256")
	}

	client := vt.NewClient(virusapikey)

	file, err := client.GetObject(vt.URL("files/%s", *sha256))
	if err != nil {
		return VirusTotalResult{
			Found:   false,
			Message: err.Error(),
		}, nil
	}

	ls, err := file.GetTime("last_submission_date")
	if err == nil {
		fmt.Printf(
			"File %s was submitted for the last time on %v\n",
			file.ID(),
			ls,
		)
	}

	rawStats, err := file.Get("last_analysis_stats")
	if err != nil {
		return VirusTotalResult{}, err
	}

	statsMap, ok := rawStats.(map[string]any)
	if !ok {
		return VirusTotalResult{}, fmt.Errorf("unexpected VirusTotal response")
	}

	result := VirusTotalResult{
		Found: true,
		Stats: AnalysisStats{
			Harmless:   int(statsMap["harmless"].(float64)),
			Malicious:  int(statsMap["malicious"].(float64)),
			Suspicious: int(statsMap["suspicious"].(float64)),
			Undetected: int(statsMap["undetected"].(float64)),
		},
	}

	return result, nil
}

func AnalyzeAttachments(env *enmime.Envelope) (Attachments, error) {
	attachments := make(Attachments, 0, len(env.Attachments))

	for _, att := range env.Attachments {
		hash := sha256.Sum256(att.Content)
		hashString := hex.EncodeToString(hash[:])

		results, err := virusTotal(&hashString)
		if err != nil {
			log.Println(err)
			continue
		}

		attachments = append(attachments, Attachment{
			Filename:    att.FileName,
			ContentType: att.ContentType,
			Hash:        hashString,
			Results:     results,
		})
	}
	return attachments, nil

}
