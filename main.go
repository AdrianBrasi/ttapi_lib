package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
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

const (
	apiBaseURL    = "https://api.cert.tastyworks.com"
	loginEndpoint = "/sessions"
)

type TastyClient struct {
	httpClient   *http.Client
	sessionToken string
}

func NewTastyClient() *TastyClient {
	return &TastyClient{
		httpClient: &http.Client{},
	}
}

func (c *TastyClient) Login(username, password string) (*LoginResponse, error) {
	loginPayload := LoginRequest{
		Login:      username,
		Password:   password,
		RememberMe: true,
	}

	payloadBytes, err := json.Marshal(loginPayload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}

	req, err := http.NewRequest("POST", apiBaseURL+loginEndpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %s: %s", resp.Status, string(body))
	}

	var loginResp LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	c.sessionToken = loginResp.Data.SessionToken
	return &loginResp, nil
}

func (c *TastyClient) KillSession() error {
	if c.sessionToken == "" {
		return fmt.Errorf("Cannot Kill session because the session token is not present")
	}

	req, err := http.NewRequest("DELETE", apiBaseURL+loginEndpoint, nil)
	if err != nil {
		return fmt.Errorf("Failed to create request: %w", err)
	}

	req.Header.Set("Authorization", c.sessionToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Failed to close the session: %w", string(body))
	}
	return nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	username := os.Getenv("TASTY_USERNAME")
	password := os.Getenv("TASTY_PASSWORD")

	if username == "" || password == "" {
		log.Fatal("TASTY_USERNAME and TASTY_PASSWORD must be set in the .env file")
	}

	client := NewTastyClient()
	loginResp, err := client.Login(username, password)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	fmt.Printf("Session Token: %s\n", loginResp.Data.SessionToken)
	fmt.Printf("Remember Token: %s\n", loginResp.Data.RememberToken)
	fmt.Printf("Email: %s\n", loginResp.Data.User.Email)
	fmt.Printf("Session expiration: %s\n", loginResp.Data.SessionExpiration)
}
