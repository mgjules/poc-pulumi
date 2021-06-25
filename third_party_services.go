package main

type ThirdPartyServices struct {
	DataDog DataDog `json:"datadog"`
}

type DataDog struct {
	Enabled    bool
	ApiKey     string `json:"api_key"`
	AppKey     string `json:"app_key"`
	ApiBaseURL string `json:"api_base_url"`
	LogBaseURL string `json:"log_base_url"`
}
