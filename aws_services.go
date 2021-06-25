package main

type AwsServices struct {
	Route53       Route53       `json:"route53"`
	Bastion       Bastion       `json:"bastion"`
	ECS           ECS           `json:"ecs"`
	ElasticSearch ElasticSearch `json:"es"`
	RDS           RDS           `json:"rds"`
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

type ElasticSearch struct {
	Enabled bool `json:"enabled"`
}

type RDS struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
	Postgres bool   `json:"postgres"`
}
