package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optdestroy"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optpreview"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optrefresh"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optup"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	log "github.com/sirupsen/logrus"
)

func createEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		environment
		credentials
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"result": err.Error()})
			return
		}

		if err := req.environment.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"result": err.Error()})
			return
		}

		req.credentials.SetDefaults(cfg)
		req.environment.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := req.Name

		s, err := auto.NewStackInlineSource(ctx, envName, _projectName, infra(req.environment, req.credentials), opts...)
		if err != nil {
			// if stack already exists, 409
			if auto.IsCreateStack409Error(err) {
				c.JSON(http.StatusConflict, gin.H{"result": fmt.Sprintf("environment %q already exists", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		go func() {
			start := time.Now()

			res, err := s.Up(context.Background(), optup.ProgressStreams(os.Stdout))
			if err != nil {
				// c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
				log.Errorf("create env %q: %v", envName, err)
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while creating environment %q", envName)), req.SlackWebHook)
				return
			}

			msg := fmt.Sprintf("Created environment %q with %v services on Domain %q in %s", envName, len(req.RsbServices.Services), req.AwsServices.Route53.Domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook([]byte(msg), req.SlackWebHook)

			result := res.Outputs["result"].Value.(map[string]interface{})
			sendToSlackWebHook([]byte(createOverview(result)), req.SlackWebHook)
		}()

		c.JSON(http.StatusOK, gin.H{
			"result": fmt.Sprintf("environment %q is being created", envName),
		})
	}
}

func listEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		credentials
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"result": err.Error()})
			return
		}

		req.credentials.SetDefaults(cfg)

		ctx := c.Request.Context()

		ws, err := auto.NewLocalWorkspace(ctx, opts...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		_ = ws.SetConfig(ctx, "", "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = ws.SetConfig(ctx, "", "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = ws.SetConfig(ctx, "", "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		stacks, err := ws.ListStacks(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"result": stacks,
		})
	}
}

func getEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}, credentials{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"result": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"result": outs["result"].Value,
		})
	}
}

func exportEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}, credentials{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"result": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		dep, err := s.Export(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		if dep.Version != 3 {
			c.JSON(http.StatusInternalServerError, gin.H{"result": "expected deployment version 3"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"result": dep.Deployment,
		})
	}
}

func historyEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}, credentials{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"result": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		history, err := s.History(ctx, 0, 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"result": history,
		})
	}
}

func previewEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		environment
		credentials
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"result": err.Error()})
			return
		}

		if err := req.environment.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"result": err.Error()})
			return
		}

		req.credentials.SetDefaults(cfg)
		req.environment.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(req.environment, req.credentials), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"result": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		result, ok := outs["result"].Value.(map[string]interface{})
		if !ok {
			log.Errorf("can't retrieve stored output for env %q", envName)
			c.JSON(http.StatusInternalServerError, gin.H{"result": "Error retrieving stored output. Try updating the environment again to regenerate the output."})
			return
		}

		slackWebHook, ok := result["slack_webhook"].(string)
		if !ok {
			log.Warnf("can't retrieve slack webhook for env %q", envName)
		}

		domain, ok := result["domain"].(string)
		if !ok {
			log.Warnf("can't retrieve domain for env %q", envName)
		}

		go func() {
			start := time.Now()

			_, err = s.Preview(context.Background() /*optpreview.Diff(),*/, optpreview.ProgressStreams(os.Stdout))
			if err != nil {
				// c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
				log.Errorf("preview env %q: %v", envName, err)
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while previewing environment %q", envName)), slackWebHook)
				return
			}

			msg := fmt.Sprintf("Previewed environment %q on Domain %q in %s", envName, domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook([]byte(msg), slackWebHook)
		}()

		c.JSON(http.StatusOK, gin.H{
			"result": fmt.Sprintf("environment %q is being previewed", envName),
		})
	}
}

func refreshEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}, credentials{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"result": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		result, ok := outs["result"].Value.(map[string]interface{})
		if !ok {
			log.Errorf("can't retrieve stored output for env %q", envName)
			c.JSON(http.StatusInternalServerError, gin.H{"result": "Error retrieving stored output. Try updating the environment again to regenerate the output."})
			return
		}

		slackWebHook, ok := result["slack_webhook"].(string)
		if !ok {
			log.Warnf("can't retrieve slack webhook for env %q", envName)
		}

		domain, ok := result["domain"].(string)
		if !ok {
			log.Warnf("can't retrieve domain for env %q", envName)
		}

		go func() {
			start := time.Now()

			_, err = s.Refresh(context.Background() /*optrefresh.Diff(),*/, optrefresh.ProgressStreams(os.Stdout))
			if err != nil {
				// c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
				log.Errorf("refresh env %q: %v", envName, err)
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while refreshing environment %q", envName)), slackWebHook)
				return
			}

			msg := fmt.Sprintf("Refreshed environment %q on Domain %q in %s", envName, domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook([]byte(msg), slackWebHook)
		}()

		c.JSON(http.StatusCreated, gin.H{
			"result": fmt.Sprintf("environment %q is being refreshed", envName),
		})
	}
}

func importEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		apitype.DeploymentV3
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"result": err.Error()})
			return
		}

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}, credentials{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"result": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		result, ok := outs["result"].Value.(map[string]interface{})
		if !ok {
			log.Errorf("can't retrieve stored output for env %q", envName)
			c.JSON(http.StatusInternalServerError, gin.H{"result": "Error retrieving stored output. Try updating the environment again to regenerate the output."})
			return
		}

		slackWebHook, ok := result["slack_webhook"].(string)
		if !ok {
			log.Warnf("can't retrieve slack webhook for env %q", envName)
		}

		domain, ok := result["domain"].(string)
		if !ok {
			log.Warnf("can't retrieve domain for env %q", envName)
		}

		go func() {
			start := time.Now()

			marshalledStack, err := json.Marshal(req)
			if err != nil {
				// c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
				log.Errorf("marshal stack env %q: %v", envName, err)
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while marshalling stack environment %q", envName)), slackWebHook)
				return
			}

			deployment := apitype.UntypedDeployment{
				Version:    3,
				Deployment: marshalledStack,
			}

			if err := s.Import(context.Background(), deployment); err != nil {
				// c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
				log.Errorf("import env %q: %v", envName, err)
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while importing environment %q", envName)), slackWebHook)
				return
			}

			msg := fmt.Sprintf("Imported environment %q on Domain %q in %s", envName, domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook([]byte(msg), slackWebHook)
		}()

		c.JSON(http.StatusCreated, gin.H{
			"result": fmt.Sprintf("environment %q is being imported", envName),
		})
	}
}

func updateEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		environment
		credentials
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"result": err.Error()})
			return
		}

		if err := req.environment.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"result": err.Error()})
			return
		}

		req.credentials.SetDefaults(cfg)
		req.environment.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(req.environment, req.credentials), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"result": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		go func() {
			start := time.Now()

			_, err = s.Up(context.Background() /*optup.Diff(),*/, optup.ProgressStreams(os.Stdout))
			if err != nil {
				if auto.IsConcurrentUpdateError(err) {
					// c.JSON(http.StatusConflict, gin.H{"result": fmt.Sprintf("environment %q already has update in progress", envName)})
					sendToSlackWebHook([]byte(fmt.Sprintf("Environment %q already has update in progress", envName)), req.SlackWebHook)
					return
				}

				// c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
				log.Errorf("update env %q: %v", envName, err)
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while updating environment %q", envName)), req.SlackWebHook)
				return
			}

			msg := fmt.Sprintf("Updated environment %q with %v services on Domain %q in %s", envName, len(req.RsbServices.Services), req.AwsServices.Route53.Domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook([]byte(msg), req.SlackWebHook)
		}()

		c.JSON(http.StatusOK, gin.H{
			"result": fmt.Sprintf("environment %q is being updated", envName),
		})
	}
}

func deleteEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}, credentials{}), opts...)
		if err != nil {
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"result": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
			return
		}

		result, ok := outs["result"].Value.(map[string]interface{})
		if !ok {
			log.Errorf("can't retrieve stored output for env %q", envName)
			c.JSON(http.StatusInternalServerError, gin.H{"result": "Error retrieving stored output. Try updating the environment again to regenerate the output."})
			return
		}

		slackWebHook, ok := result["slack_webhook"].(string)
		if !ok {
			log.Warnf("can't retrieve slack webhook for env %q", envName)
		}

		domain, ok := result["domain"].(string)
		if !ok {
			log.Warnf("can't retrieve domain for env %q", envName)
		}

		go func() {
			start := time.Now()

			ctx := context.Background()

			if _, err := s.Destroy(ctx, optdestroy.ProgressStreams(os.Stdout)); err != nil {
				// 	c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
				log.Errorf("destroy env %q: %v", envName, err)
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while deleting environment %q", envName)), slackWebHook)
				return
			}

			if err = s.Workspace().RemoveStack(ctx, envName); err != nil {
				// c.JSON(http.StatusInternalServerError, gin.H{"result": err.Error()})
				log.Errorf("remove stack env %q: %v", envName, err)
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while removing stack for environment %q", envName)), slackWebHook)
				return
			}

			msg := fmt.Sprintf("Deleted environment %q on Domain %q in %s", envName, domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook([]byte(msg), slackWebHook)
		}()

		c.JSON(http.StatusOK, gin.H{
			"result": fmt.Sprintf("environment %q is being deleted", envName),
		})
	}
}
