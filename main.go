package main

import (
	"context"
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

	if err := installPulumiPlugins(context.TODO()); err != nil {
		return fmt.Errorf("installing pulumi plugins: %w", err)
	}

	project := auto.Project(workspace.Project{
		Name:    tokens.PackageName(_projectName),
		Runtime: workspace.NewProjectRuntimeInfo("go", nil),
		Backend: &workspace.ProjectBackend{
			URL: cfg.BackendURL,
		},
	})

	workDir := auto.WorkDir(".")

	router := gin.Default()

	api := router.Group("/api")
	{
		api.POST("/environments", createEnvironment(cfg, project, workDir))
		api.GET("/environments", listEnvironment(cfg, project, workDir))
		api.GET("/environments/history/:name", historyEnvironment(cfg, project, workDir))
		api.GET("/environments/export/:name", exportEnvironment(cfg, project, workDir))
		api.GET("/environments/:name", getEnvironment(cfg, project, workDir))
		api.POST("/environments/preview/:name", previewEnvironment(cfg, project, workDir))
		api.POST("/environments/refresh/:name", refreshEnvironment(cfg, project, workDir))
		api.POST("/environments/import/:name", importEnvironment(cfg, project, workDir))
		api.PUT("/environments/:name", updateEnvironment(cfg, project, workDir))
		api.DELETE("/environments/:name", deleteEnvironment(cfg, project, workDir))
	}

	if err := router.Run(fmt.Sprintf(":%d", cfg.Port)); err != nil {
		return err
	}

	return nil
}

func installPulumiPlugins(ctx context.Context) error {
	w, err := auto.NewLocalWorkspace(ctx)
	if err != nil {
		return err
	}

	if err := w.InstallPlugin(ctx, "aws", "v4.9.0"); err != nil {
		return err
	}

	if err := w.InstallPlugin(ctx, "github", "v4.2.0"); err != nil {
		return err
	}

	if err := w.InstallPlugin(ctx, "random", "v4.2.0"); err != nil {
		return err
	}

	return nil
}
