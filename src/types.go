package main

type Config struct {
	KeyPath          string
	Port             string
	Issuer           string
	Discord          Discord
	AllowedRedirects []string
}

type Discord struct {
	ClientId     string
	ClientSecret string
	RedirectURL  string
}
