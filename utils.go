package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"html"

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

// Filtrar y limpiar URLs antes de escanear
func CleanAndFilterURLs(urls []string) []string {
	skip := []string{
		"schema.org",
		"googleusercontent.com",
		"gstatic.com",
	}

	seen := map[string]bool{}
	result := []string{}

	for _, u := range urls {
		clean := html.UnescapeString(u)

		// Quitar caracteres basura al final
		clean = strings.TrimRight(clean, ").],; \t\n")

		// Validar URL
		parsed, err := url.Parse(clean)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}

		// Deduplicar por host+path
		key := parsed.Host + parsed.Path
		if seen[key] {
			continue
		}

		// Saltar dominios de infraestructura
		skipURL := false
		for _, s := range skip {
			if strings.Contains(clean, s) {
				skipURL = true
				break
			}
		}
		if skipURL {
			continue
		}

		seen[key] = true
		result = append(result, clean)
	}

	return result
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
	urls := CleanAndFilterURLs(resultado)

	return urls
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

func AnalyzeSecurity(auth AuthVerdict, attachments Attachments, urls []URLScanResult) SecurityAssessment {

	score := 100
	reasons := []string{}

	// SPF
	if auth.SPF != "pass" {
		score -= 25
		reasons = append(reasons, "SPF validation failed")
	}

	// DKIM
	if auth.DKIM != "pass" {
		score -= 25
		reasons = append(reasons, "DKIM validation failed")
	}

	// DMARC
	if auth.DMARC != "pass" {
		score -= 30
		reasons = append(reasons, "DMARC validation failed")
	}

	// URLs
	for _, url := range urls {

		if url.Verdicts.Overall.Malicious {
			score -= 50
			reasons = append(reasons, "Malicious URL detected")
		}

		if url.Verdicts.Urlscan.Malicious {
			score -= 40
			reasons = append(reasons, "URL flagged by URLScan")
		}

		if url.Verdicts.Engines.Malicious {
			score -= 40
			reasons = append(reasons, "URL flagged by security engines")
		}
	}

	for _, attachment := range attachments {

		if !attachment.Results.Found {
			reasons = append(
				reasons,
				fmt.Sprintf(
					"Attachment %s not found in VirusTotal",
					attachment.Filename,
				),
			)

			continue
		}
	}

	if score < 0 {
		score = 0
	}

	message := "Healthy"

	switch {
	case score >= 90:
		message = "Healthy"
	case score >= 70:
		message = "Low Risk"
	case score >= 40:
		message = "Suspicious"
	default:
		message = "Malicious"
	}

	return SecurityAssessment{
		Message:   message,
		RiskScore: score,
		Reasons:   reasons,
	}
}
