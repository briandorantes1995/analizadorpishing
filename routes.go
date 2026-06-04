package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"

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

		sumary := Summary{
			From:              env.GetHeader("From"),
			Subject:           env.GetHeader("Subject"),
			Attachments_count: len(env.Attachments),
			URLS_count:        len(urls),
		}

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

		response := ApiResponse{
			Message:        "Healthy",
			Authentication: headers,
			Summary:        sumary,
			Attachments:    attachments,
		}

		c.JSON(http.StatusOK, response)
	})
}
