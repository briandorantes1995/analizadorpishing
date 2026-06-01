package main

import (
	"regexp"
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
