package main

type credentials struct {
	AWSAccessKeyID        string `json:"aws_access_key_id"`
	AWSSecretAccessKey    string `json:"aws_secret_access_key"`
	AWSRegion             string `json:"aws_region"`
	GithubAuthToken       string `json:"github_auth_token"`
	GithubOrgName         string `json:"github_org_name"`
	DBMasterUserPassword  string `json:"db_master_user_password"`
	RMQMasterUserPassword string `json:"rmq_master_user_password"`
}

func (c *credentials) SetDefaults(cfg config) {
	if c.AWSAccessKeyID == "" {
		c.AWSAccessKeyID = cfg.AWSAccessKeyID
	}

	if c.AWSSecretAccessKey == "" {
		c.AWSSecretAccessKey = cfg.AWSSecretAccessKey
	}

	if c.AWSRegion == "" {
		c.AWSRegion = "eu-west-1"
	}

	if c.GithubAuthToken == "" {
		c.GithubAuthToken = cfg.GithubAuthToken
	}

	if c.GithubOrgName == "" {
		c.GithubOrgName = cfg.GithubOrgName
	}
}
