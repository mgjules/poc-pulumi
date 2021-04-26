package main

type awsCredentials struct {
	AWSAccessKeyID     string `json:"aws_access_key_id"`
	AWSSecretAccessKey string `json:"aws_secret_access_key"`
	AWSRegion          string `json:"aws_region"`
}

func (a *awsCredentials) SetDefaults(cfg config) {
	if a.AWSAccessKeyID == "" {
		a.AWSAccessKeyID = cfg.AWSAccessKeyID
	}

	if a.AWSSecretAccessKey == "" {
		a.AWSSecretAccessKey = cfg.AWSSecretAccessKey
	}

	if a.AWSRegion == "" {
		a.AWSRegion = "eu-west-1"
	}
}
