package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func StartURLScans(urls []string) ([]URLScanResponse, error) {
	results := make([]URLScanResponse, 0, len(urls))

	for _, url := range urls {
		scanResp, err := StartURLScan(url)
		if err != nil {
			continue
		}

		results = append(results, *scanResp)
	}

	return results, nil
}

func StartURLScan(targetURL string) (*URLScanResponse, error) {
	apikey := os.Getenv("URLSCAN_API_KEY")

	if apikey == "" {
		return nil, fmt.Errorf("URLSCAN_API_KEY not configured")
	}

	payload := map[string]any{
		"url":        targetURL,
		"visibility": "public",
		"country":    "de",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, "https://urlscan.io/api/v1/scan/", bytes.NewBuffer(body))

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", apikey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)

	var scanResp URLScanResponse
	if err := json.Unmarshal(rawBody, &scanResp); err != nil {
		return nil, err
	}

	return &scanResp, nil
}

func GetURLScanResults(scans []URLScanResponse) ([]URLScanResult, error) {
	results := make([]URLScanResult, 0, len(scans))

	for _, scan := range scans {
		result, err := GetURLScanResult(scan.Uuid)
		if err != nil {
			fmt.Printf("Error obteniendo resultado para UUID %s: %v\n", scan.Uuid, err)
			continue
		}
		results = append(results, *result)
	}

	return results, nil
}

func GetURLScanResult(uuid string) (*URLScanResult, error) {
	apikey := os.Getenv("URLSCAN_API_KEY")

	if apikey == "" {
		return nil, fmt.Errorf("URLSCAN_API_KEY not configured")
	}
	url := fmt.Sprintf(
		"https://urlscan.io/api/v1/result/%s/",
		uuid,
	)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("API-Key", apikey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scan not ready yet: %s", resp.Status)
	}

	var result URLScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
