package main

import (
	"ca-cli/cmd"
	"log"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load("credentials.env")
	if err != nil {
		log.Fatal("Error loading .env")
	}
	cmd.Execute()
}
