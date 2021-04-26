package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/gin-gonic/gin"
	"github.com/kelseyhightower/envconfig"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
)

const _project = "bus"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var cfg config
	if err := envconfig.Process("", &cfg); err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	if err := installAWSPlugin(context.TODO()); err != nil {
		return fmt.Errorf("install AWS plugins: %w", err)
	}

	if err := loginBackend(cfg.BackendURL); err != nil {
		return fmt.Errorf("backend login: %w", err)
	}

	router := gin.Default()

	api := router.Group("/api")
	{
		api.POST("/environments", createEnvironment(cfg))
		api.GET("/environments/:name", getEnvironment(cfg))
		api.PUT("/environments/:name", updateEnvironment(cfg))
		api.DELETE("/environments/:name", deleteEnvironment(cfg))
	}

	if err := router.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		return err
	}

	return nil
}

func installAWSPlugin(ctx context.Context) error {
	w, err := auto.NewLocalWorkspace(ctx)
	if err != nil {
		return fmt.Errorf("new local workspace: %w", err)
	}

	if err := w.InstallPlugin(ctx, "aws", "v3.2.1"); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	return nil
}

func loginBackend(url string) error {
	cmd := exec.Command("pulumi", "login", url)
	return cmd.Run()
}
