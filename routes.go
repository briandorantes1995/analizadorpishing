package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jhillyerd/enmime"
)

func RegisterRoutes(r *gin.Engine) {

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Healthy",
		})
	})

	r.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"title": "Analisis de  Correos",
		})
	})

	r.POST("/analize", func(c *gin.Context) {

		fileHeader, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		file, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer file.Close()

		env, err := enmime.ReadEnvelope(file)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		headers := AnalizarCabecerasAutenticacion(env)

		urls := ExtraerURLs(env.Text, env.HTML)

		urlResults, err := StartURLScans(urls)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		time.Sleep(15 * time.Second)
		urlScanResults, err := GetURLScanResults(urlResults)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		sumary := Summary{
			From:              env.GetHeader("From"),
			Subject:           env.GetHeader("Subject"),
			Attachments_count: len(env.Attachments),
			URLS_count:        len(urls),
		}

		attachments, err := AnalyzeAttachments(env)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		result := AnalyzeSecurity(headers, attachments, urlScanResults)

		response := ApiResponse{
			Message:        result.Message,
			RiskScore:      result.RiskScore,
			Reasons:        result.Reasons,
			Summary:        sumary,
			Authentication: headers,
			Attachments:    attachments,
			UrlResults:     urlScanResults,
		}

		c.JSON(http.StatusOK, response)
	})
}
