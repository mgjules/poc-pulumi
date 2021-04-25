package main

import (
	"context"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
)

const project = "bus"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := installAWSPlugin(context.TODO()); err != nil {
		return fmt.Errorf("install AWS plugins: %w", err)
	}

	router := gin.Default()

	api := router.Group("/api")
	{
		api.POST("/environments", createEnvironment())
		api.GET("/environments/:name", getEnvironment())
		api.PUT("/environments/:name", updateEnvironment())
		api.DELETE("/environments/:name", deleteEnvironment())
	}

	if err := router.Run(":13337"); err != nil {
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
