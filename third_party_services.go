package main

type ThirdPartyServices struct {
	DataDog  DataDog  `json:"datadog"`
	Telegram Telegram `json:"telegram"`
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
