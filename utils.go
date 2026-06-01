package main

import (
	"regexp"

	"github.com/jhillyerd/enmime"
)

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

	veredicto := AuthVerdict{
		SPF:   "none",
		DKIM:  "none",
		DMARC: "none",
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
