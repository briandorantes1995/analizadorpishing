# Analizador de Correos Electrónicos

## Descripción

El objetivo de este proyecto es analizar archivos de correo electrónico en formato `.eml` para identificar posibles intentos de phishing.

Las principales funcionalidades incluyen:

* Extracción y análisis de cabeceras del correo.
* Detección y extracción de URLs contenidas en el mensaje.
* Análisis de archivos adjuntos mediante su hash SHA-256 utilizando la API de VirusTotal.
* Análisis y reputación de URLs mediante la API de urlscan.io.
* Interfaz web sencilla para facilitar la revisión de resultados.

## Despliegue con Docker Compose

1. Copie el archivo `docker-compose.yml` al entorno de ejecución.
2. Configure sus credenciales en el archivo `.env`.

### Variables de entorno requeridas

```env
VIRUSTOTAL_API_KEY=<su_api_key>
URLSCAN_API_KEY=<su_api_key>
```

## Funcionalidades implementadas

* [x] Extracción de cabeceras del correo.
* [x] Extracción de URLs.
* [x] Integración con la API de VirusTotal.
* [x] Integración con la API de urlscan.io.
* [x] Interfaz web básica utilizando plantillas (`tmpl`).

## Próximas mejoras

* [ ] Mejorar y enriquecer los resultados del análisis.
* [ ] Publicar imagen Docker en GitHub Container Registry (GHCR).
* [ ] Proporcionar un archivo `docker-compose.yml` listo para despliegue.
