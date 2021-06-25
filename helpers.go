package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const _rsbServicePrefix = "rsb-service-"

func shortName(name string) string {
	return strings.Replace(name, _rsbServicePrefix, "", 1)
}

func shortEnvName(env, name string) string {
	return fmt.Sprintf("%s-%s", env, shortName(name))
}

func sendToSlackWebHook(message []byte, hookURL string) error {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	m := make(map[string]string)
	m["text"] = string(message)
	data, err := json.Marshal(m)
	if err != nil {
		log.Errorf("marshal text for slack: %v", err)
		return fmt.Errorf("marshal text for slack: %w", err)
	}

	req, err := http.NewRequest("POST", hookURL, bytes.NewBuffer(data))
	if err != nil {
		log.Errorf("create http request: %v", err)
		return err
	}

	req.Header.Set("Content-type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Errorf("send request to slack: %v", err)
		return err
	}
	defer resp.Body.Close()

	log.Debug("Message sent to Slack")
	return nil
}

func createOverview(result map[string]interface{}) string {
	overview := fmt.Sprintf("ℹ️ Here is an overview of environment *%s*:\n", result["name"])
	overview += fmt.Sprintf("*RabbitMQ admin:*\n%s (U: %s P: %s)\n", fmt.Sprintf("http(s)://%s/", result["broker_admin_ui"]), result["broker_username"], result["broker_admin_password"])
	overview += fmt.Sprintf("*RabbitMQ server:*\n%s (U: %s P: %s)\n", result["broker_server"], result["broker_username"], result["broker_admin_password"])

	overview += "\n\n*Services*\n\n"
	for svcName, svc := range result["services_routes"].(map[string]interface{}) {
		overview += fmt.Sprintf("Service %q is available at: https://%s (%s)\n", svcName, svc, result["loadbalancer"])
	}

	return overview
}
