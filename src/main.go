package main

import (
	"log"
	"net/http"

	"github.com/BurntSushi/toml"
)

func main() {
	var config Config
	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	log.Printf("Loaded config successfully.")

	handler, err := NewOAuthHandler(&config)
	if err != nil {
		log.Fatalf("Error initializing OAuth handler: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", handler.HandleLogin)
	mux.HandleFunc("GET /callback", handler.HandleCallback)
	mux.HandleFunc("POST /refresh", handler.HandleRefresh)

	addr := ":" + config.Port
	log.Printf("Server starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
