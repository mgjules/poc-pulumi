package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

func sendToSlackWebHook(message string, hookURL string) error {
	if message == "" {
		log.Error("message can't be empty")
		return errors.New("message can't be empty")
	}

	if hookURL == "" {
		log.Error("hookURL can't be empty")
		return errors.New("hookURL can't be empty")
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}

	m := map[string]string{
		"text": message,
	}
	marshalledMessage, err := json.Marshal(m)
	if err != nil {
		log.Errorf("marshal message for slack: %v", err)
		return fmt.Errorf("marshal message for slack: %w", err)
	}

	req, err := http.NewRequest("POST", hookURL, bytes.NewBuffer(marshalledMessage))
	if err != nil {
		log.Errorf("create http request for slack webhook: %v", err)
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
	overview += fmt.Sprintf("*RabbitMQ admin:*\n%s (U: %s P: %s)\n", result["broker_admin_ui"], result["broker_username"], result["broker_admin_password"])
	overview += fmt.Sprintf("*RabbitMQ server:*\n%s (U: %s P: %s)\n", result["broker_server"], result["broker_username"], result["broker_admin_password"])

	overview += "\n\n*Services*\n\n"
	for svcName, svc := range result["services_routes"].(map[string]interface{}) {
		overview += fmt.Sprintf("Service %q is available at: https://%s (%s)\n", svcName, svc, result["loadbalancer"])
	}

	return overview
}
