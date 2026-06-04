package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/jhillyerd/enmime"
)

func fetchIp(ip string) (*IPInfo, error) {
	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

func StartURLScan(targetURL, apiKey string) (*URLScanResponse, error) {
	apikey := os.Getenv("URLSCAN_API_KEY")

	if apikey == "" {
		return nil, fmt.Errorf("URLSCAN_API_KEY not configured")
	}

	payload := map[string]any{
		"url":        targetURL,
		"visibility": "public",
		"country":    "mx",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		"https://urlscan.io/api/v1/scan/",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var scanResp URLScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, err
	}

	return &scanResp, nil
}

func GetURLScanResult(uuid, apiKey string) (*URLScanResult, error) {
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

	req.Header.Set("API-Key", apiKey)

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

func ExtraerURLs(texto string, html string) []string {
	// Expresión regular estándar para capturar URLs (http o https)
	re := regexp.MustCompile(`https?://[^\s<>"]+`)

	urlsUnicas := make(map[string]bool)

	// Buscar en el texto plano
	matchesText := re.FindAllString(texto, -1)
	for _, url := range matchesText {
		urlsUnicas[url] = true
	}

	// Buscar en el HTML
	matchesHTML := re.FindAllString(html, -1)
	for _, url := range matchesHTML {
		urlsUnicas[url] = true
	}

	// Convertir el mapa a un slice de strings
	var resultado []string
	for url := range urlsUnicas {
		resultado = append(resultado, url)
	}

	return resultado
}

func AnalizarCabecerasAutenticacion(envelope *enmime.Envelope) AuthVerdict {
	// Enmime permite obtener los headers sin importar las mayúsculas/minúsculas
	authHeader := envelope.GetHeader("Authentication-Results")

	if authHeader == "" {
		return AuthVerdict{SPF: "unknown", DKIM: "unknown", DMARC: "unknown"}
	}

	// Expresiones regulares para buscar el veredicto de cada uno
	reSPF := regexp.MustCompile(`spf=([a-z]+)`)
	reDKIM := regexp.MustCompile(`dkim=([a-z]+)`)
	reDMARC := regexp.MustCompile(`dmarc=([a-z]+)`)
	reIP := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	veredicto := AuthVerdict{
		SPF:   "none",
		DKIM:  "none",
		DMARC: "none",
	}

	ip := reIP.FindString(authHeader)
	if ip != "" {
		fmt.Printf("IP encontrada en Authentication-Results: %s\n", ip)
		ipInfo, err := fetchIp(ip)
		if err != nil {
			veredicto.IP = nil
		} else {
			veredicto.IP = ipInfo
		}
	}

	// Buscar SPF
	if match := reSPF.FindStringSubmatch(authHeader); len(match) > 1 {
		veredicto.SPF = match[1]
	}
	// Buscar DKIM
	if match := reDKIM.FindStringSubmatch(authHeader); len(match) > 1 {
		veredicto.DKIM = match[1]
	}
	// Buscar DMARC
	if match := reDMARC.FindStringSubmatch(authHeader); len(match) > 1 {
		veredicto.DMARC = match[1]
	}

	return veredicto
}
