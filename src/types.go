package main

type Config struct {
	KeyPath string
	Port    string
	Discord Discord
}

type Discord struct {
	ClientId     string
	ClientSecret string
	RedirectURL  string
}
