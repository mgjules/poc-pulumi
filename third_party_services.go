package main

type ThirdPartyServices struct {
	DataDog   DataDog   `json:"datadog"`
	Telegram  Telegram  `json:"telegram"`
	CloudAMQP CloudAMQP `json:"cloudAMQP"`
}

type DataDog struct {
	Enabled    bool
	ApiKey     string `json:"api_key"`
	AppKey     string `json:"app_key"`
	ApiBaseURL string `json:"api_base_url"`
	LogBaseURL string `json:"log_base_url"`
}

type Telegram struct {
	BotID  string `json:"bot_id"`
	ChatID string `json:"chat_id"`
}

type CloudAMQP struct {
	InstanceName   string `json:"instance_name"`
	InstanceNodes  int    `json:"instance_nodes"`
	InstanceRegion string `json:"instance_region"`
	InstanceSubnet string `json:"instance_subnet"`
	InstanceType   string `json:"instance_type"`
	CustomerApiKey string `json:"customer_api_key"`
}
