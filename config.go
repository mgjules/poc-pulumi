package main

type config struct {
	AWSAccessKeyID     string `envconfig:"AWS_ACCESS_KEY_ID" required:"true"`
	AWSSecretAccessKey string `envconfig:"AWS_SECRET_ACCESS_KEY" required:"true"`
	AWSRegion          string `envconfig:"AWS_REGION"`
	GithubOrgName      string `envconfig:"GITHUBORGNAME" required:"true"`
	GithubAuthToken    string `envconfig:"GITHUBOAUTHTOKEN" required:"true"`
	DNSDomain          string `envconfig:"DNSDOMAIN"`
	DNSZoneID          string `envconfig:"DNSZONEID"`
	BackendURL         string `envconfig:"BACKEND_URL" required:"true"`
	Port               int    `envconfig:"PORT" default:"8080"`
}
