package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

var DiscordEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/api/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

type TokenStore struct {
	UserID       string    `json:"user_id"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry,omitzero"`
}

type OAuthHandler struct {
	Config     *Config
	OAuth      *oauth2.Config
	PrivateKey *rsa.PrivateKey
}

func NewOAuthHandler(config *Config) (*OAuthHandler, error) {
	keyData, err := os.ReadFile(config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &OAuthHandler{
		Config:     config,
		PrivateKey: privKey,
		OAuth: &oauth2.Config{
			ClientID:     config.Discord.ClientId,
			ClientSecret: config.Discord.ClientSecret,
			RedirectURL:  config.Discord.RedirectURL,
			Endpoint:     DiscordEndpoint,
			Scopes:       []string{"identify"},
		},
	}, nil
}

func (h *OAuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	url := h.OAuth.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *OAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	token, err := h.OAuth.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	userID, err := h.fetchUserID(token.AccessToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch user ID: %v", err), http.StatusInternalServerError)
		return
	}

	err = h.saveToken(userID, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save token: %v", err), http.StatusInternalServerError)
		return
	}

	accessToken, err := h.generateJWT(userID, 15*time.Minute)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.generateJWT(userID, 7*24*time.Hour)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (h *OAuthHandler) generateJWT(userID string, duration time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(h.PrivateKey)
}

func (h *OAuthHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token, err := jwt.ParseWithClaims(req.RefreshToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return &h.PrivateKey.PublicKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		http.Error(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	newAccessToken, err := h.generateJWT(claims.Subject, 15*time.Minute)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": newAccessToken,
	})
}

func (h *OAuthHandler) fetchUserID(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discord API returned status: %s", resp.Status)
	}

	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", err
	}

	return user.ID, nil
}

func (h *OAuthHandler) saveToken(userID string, token *oauth2.Token) error {
	store := TokenStore{
		UserID:       userID,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("tokens", 0755); err != nil {
		return err
	}

	filename := filepath.Join("tokens", userID+".json")
	return os.WriteFile(filename, data, 0644)
}

func (h *OAuthHandler) LoadToken(userID string) (*oauth2.Token, error) {
	filename := filepath.Join("tokens", userID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var store TokenStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	return &oauth2.Token{
		RefreshToken: store.RefreshToken,
		Expiry:       store.Expiry,
		TokenType:    "Bearer",
	}, nil
}
