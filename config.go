package main

type config struct {
	GithubAuthToken string `envconfig:"GITHUBORGNAME" required:"true"`
	GithubOrgName   string `envconfig:"GITHUBOAUTHTOKEN" required:"true"`
	DNSDomain       string `envconfig:"DNSDOMAIN"`
	DNSZoneID       string `envconfig:"DNSZONEID"`
	BackendURL      string `envconfig:"BACKEND_URL" required:"true"`
	Port            int    `envconfig:"PORT" default:"8080"`
}
