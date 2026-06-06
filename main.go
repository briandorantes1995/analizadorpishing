package main

import (
	"embed"
	"html/template"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var templateFS embed.FS

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	r := gin.Default()
	r.MaxMultipartMemory = 50 << 20
	templ := template.Must(template.New("").ParseFS(templateFS, "templates/*"))
	r.SetHTMLTemplate(templ)

	RegisterRoutes(r)

	r.Run(":8080")
}
