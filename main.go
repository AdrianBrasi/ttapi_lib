package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type LoginRequest struct {
	Login      string `json:"login"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember-me"`
}

type LoginResponse struct {
	Data struct {
		User struct {
			Email      string `json:"email"`
			Username   string `json:"username"`
			ExternalID string `json:"external-id"`
		} `json:"user"`
		SessionToken      string    `json:"session-token"`
		RememberToken     string    `json:"remember-token"`
		SessionExpiration time.Time `json:"session-expiration"`
	} `json:"data"`
	Context string `json:"context"`
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	username := os.Getenv("TASTY_USERNAME")
	password := os.Getenv("TASTY_PASSWORD")

	if username == "" {
		log.Fatal("TASTY_USERNAME is not set in the .env file")
	}
	if password == "" {
		log.Fatal("TASTY_PASSWORD is not set in the .env file")
	}

	loginPayload := LoginRequest{
		Login:      username,
		Password:   password,
		RememberMe: true,
	}

	payloadBytes, err := json.Marshal(loginPayload)
	if err != nil {
		log.Fatalf("Error marshalling payload: %v", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://api.cert.tastyworks.com/sessions", bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Fatalf("Http Request to tastyworks failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error loading response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Request failed: %s\n%s", resp.Status, string(body))
	}

	var loginResp LoginResponse
	err = json.Unmarshal(body, &loginResp)
	if err != nil {
		log.Fatalf("Error unmarshalling the response: %v", err)
	}
	fmt.Printf("Session Token: %s\n", loginResp.Data.SessionToken)
	fmt.Printf("Email: %s\n", loginResp.Data.User.Email)
	fmt.Printf("Session expiration: %s\n", loginResp.Data.SessionExpiration)
}
