package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jhillyerd/enmime"
)

func main() {
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
		log.Println(fileHeader.Filename)
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

		// Headers can be retrieved via Envelope.GetHeader(name).
		fmt.Printf("From: %v\n", env.GetHeader("From"))

		// Address-type headers can be parsed into a list of decoded mail.Address structs.
		alist, _ := env.AddressList("To")
		for _, addr := range alist {
			fmt.Printf("To: %s <%s>\n", addr.Name, addr.Address)
		}

		// enmime can decode quoted-printable headers.
		fmt.Printf("Subject: %v\n", env.GetHeader("Subject"))

		// The plain text body is available as mime.Text.
		fmt.Printf("Text Body: %v chars\n", len(env.Text))

		// The HTML body is stored in mime.HTML.
		fmt.Printf("HTML Body: %v chars\n", len(env.HTML))

		// mime.Inlines is a slice of inlined attacments.
		fmt.Printf("Inlines: %v\n", len(env.Inlines))

		// mime.Attachments contains the non-inline attachments.
		fmt.Printf("Attachments: %v\n", len(env.Attachments))

		attachments := make([]Attachment, len(env.Attachments))

		for _, att := range env.Attachments {
			hash := sha256.Sum256(att.Content)
			hashString := hex.EncodeToString(hash[:])
			attachments = append(attachments, Attachment{
				Filename:    att.FileName,
				ContentType: att.ContentType,
				Hash:        hashString,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"message":     "Healthy",
			"attachments": attachments,
		})

	})

	r.Run(":8080")
}
