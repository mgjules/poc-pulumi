package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
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

func uploadLogs(ctx context.Context, content io.Reader, envName string, logType string, cfg config, msg, slackWebhooURL string, timeLogged time.Time) error {
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, ""),
		Region:      aws.String(cfg.AWSRegion),
	})
	if err != nil {
		return fmt.Errorf("create new aws session: %v", err)
	}

	uploader := s3manager.NewUploader(sess)

	result, err := uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket: aws.String(strings.ReplaceAll(cfg.BackendURL, "s3://", "")),
		Key:    aws.String(fmt.Sprintf("logs/%s/%s/%s.log.gz", envName, logType, timeLogged.Format(filenameTimeFormat))),
		Body:   content,
	})
	if err != nil {
		return fmt.Errorf("upload logs: %v", err)
	}

	return sendToSlackWebHook(fmt.Sprintf("%s\nView logs: %s", msg, result.Location), slackWebhooURL)
}
