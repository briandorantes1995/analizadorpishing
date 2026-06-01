package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jhillyerd/enmime"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading directly from system environment")
	}

	r := gin.Default()
	r.MaxMultipartMemory = 50 << 20

	r.GET("/health", func(c *gin.Context) {
		// Return JSON response
		c.JSON(http.StatusOK, gin.H{
			"message": "Healthy",
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
			fmt.Print(err)
			return
		}

		headers := AnalizarCabecerasAutenticacion(env)
		fmt.Printf("Authentication-Results: SPF=%s, DKIM=%s, DMARC=%s\n", headers.SPF, headers.DKIM, headers.DMARC)
		fmt.Printf("%+v\n", headers.IP)
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
				log.Fatal(err)
			}
			attachments = append(attachments, Attachment{
				Filename:    att.FileName,
				ContentType: att.ContentType,
				Hash:        hashString,
				Results:     results,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"message":     "Healthy",
			"summary":     sumary,
			"attachments": attachments,
		})

	})

	r.Run(":8080")
}
