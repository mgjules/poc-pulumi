package main

type AwsServices struct {
	Route53   Route53   `json:"route53"`
	Bastion   Bastion   `json:"bastion"`
	Codebuild Codebuild `json:"codebuild"`
	ECS       ECS       `json:"ecs"`
	ES        ES        `json:"es"`
	RDS       RDS       `json:"rds"`
	SNS       SNS       `json:"sns"`
}

type Route53 struct {
	Domain    string `json:"domain"`
	DNSZoneID string `json:"dns_zone_id"`
}

type Bastion struct {
	AMIID string `json:"ami_id"`
}

type ECS struct {
	CPU        int `json:"cpu"`
	Memory     int `json:"memory"`
	VolumeSize int `json:"volume_size"`
}

type ES struct {
	Enabled bool   `json:"enabled"`
	Version string `json:"version"`
}

type RDS struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
	Postgres bool   `json:"postgres"`
}

type SNS struct {
	Subscriptions []SNSSubscription `json:"subscriptions"`
}

type SNSSubscription struct {
	Endpoint string `json:"endpoint"`
	Protocol string `json:"protocol"`
}

type Codebuild struct {
	Image string `json:"image"`
}
