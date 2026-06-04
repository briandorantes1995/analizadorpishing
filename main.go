package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	r := gin.Default()
	r.MaxMultipartMemory = 50 << 20
	r.LoadHTMLGlob("templates/*")

	RegisterRoutes(r)

	r.Run(":8080")
}
