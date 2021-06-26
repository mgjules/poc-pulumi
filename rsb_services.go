package main

type RsbServices struct {
	CORSOriginURLs string       `json:"cors_origin_urls"`
	Broker         Broker       `json:"broker"`
	Services       []RsbService `json:"services"`
}

type Broker struct {
	Driver    string `json:"driver"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Port      int    `json:"port"`
	AdminPort int    `json:"admin_port"`
}

type RsbService struct {
	Name         string `json:"name"`
	SourceBranch string `json:"source_branch"`
	SourceCommit string `json:"source_commit"`
	Count        int    `json:"count"`
}
