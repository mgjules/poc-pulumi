package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/kelseyhightower/envconfig"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

const _projectName = "bus"

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

	project := auto.Project(workspace.Project{
		Name:    tokens.PackageName(_projectName),
		Runtime: workspace.NewProjectRuntimeInfo("go", nil),
		Backend: &workspace.ProjectBackend{
			URL: cfg.BackendURL,
		},
	})

	router := gin.Default()

	api := router.Group("/api")
	{
		api.POST("/environments", createEnvironment(cfg, project, auto.WorkDir(".")))
		api.GET("/environments/:name", getEnvironment(cfg, project, auto.WorkDir(".")))
		api.PUT("/environments/:name", updateEnvironment(cfg, project, auto.WorkDir(".")))
		api.DELETE("/environments/:name", deleteEnvironment(cfg, project, auto.WorkDir(".")))
	}

	if err := router.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		return err
	}

	return nil
}
