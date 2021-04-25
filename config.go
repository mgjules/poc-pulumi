package main

type config struct {
	BackendURL string `envconfig:"BACKEND_URL" required:"true"`
	Port       int    `envconfig:"PORT" default:"8080"`
}
