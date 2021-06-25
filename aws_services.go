package main

type AwsServices struct {
	ElasticSearch ElasticSearch `json:"es"`
	RDS           RDS           `json:"rds"`
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
