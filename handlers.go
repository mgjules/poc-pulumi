package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
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

const filenameTimeFormat = "20060102T150405Z"

func createEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		environment
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := req.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		req.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := req.Name

		s, err := auto.NewStackInlineSource(ctx, envName, _projectName, infra(req.environment), opts...)
		if err != nil {
			// if stack already exists, 409
			if auto.IsCreateStack409Error(err) {
				c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("environment %q already exists", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		go func() {
			start := time.Now()

			sendToSlackWebHook(
				fmt.Sprintf("Creating environment %q with %v services on Domain %q...", envName, len(req.RsbServices.Services), req.AwsServices.Route53.Domain),
				req.SlackWebHook,
			)

			var msg strings.Builder
			ctx := context.Background()

			inMemoryStore := bytes.NewBuffer([]byte{})
			gzipWriter, _ := gzip.NewWriterLevel(inMemoryStore, gzip.BestCompression)

			defer func() {
				gzipWriter.Close()

				if err := uploadLogs(ctx, inMemoryStore, envName, "create", cfg, msg.String(), req.SlackWebHook, start); err != nil {
					log.Error(err)
				}
			}()

			res, err := s.Up(ctx, optup.ProgressStreams(os.Stdout, gzipWriter))
			if err != nil {
				log.Errorf("create env %q: %v", envName, err)
				msg.WriteString(fmt.Sprintf("Error occured while creating environment %q", envName))
				return
			}

			success := fmt.Sprintf("Created environment %q with %v services on Domain %q in %s", envName, len(req.RsbServices.Services), req.AwsServices.Route53.Domain, time.Since(start))
			log.Infof(success)
			msg.WriteString(success)

			result := res.Outputs["result"].Value.(map[string]interface{})
			msg.WriteString("\n" + createOverview(result))
		}()

		c.JSON(http.StatusOK, gin.H{
			"result": fmt.Sprintf("environment %q is being created", envName),
		})
	}
}

func listEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		environment
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		req.SetDefaults(cfg)

		ctx := c.Request.Context()

		ws, err := auto.NewLocalWorkspace(ctx, opts...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		_ = ws.SetConfig(ctx, "", "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = ws.SetConfig(ctx, "", "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = ws.SetConfig(ctx, "", "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		stacks, err := ws.ListStacks(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		info, err := s.Info(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"result": gin.H{
				"outputs": outs["result"].Value,
				"info":    info,
			},
		})
	}
}

func exportEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		dep, err := s.Export(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if dep.Version != 3 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "expected deployment version 3"})
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

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		page, _ := strconv.Atoi(c.DefaultQuery("page", "0"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("pagesize", "0"))

		history, err := s.History(ctx, pageSize, page)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := req.environment.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		req.environment.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(req.environment), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		result, ok := outs["result"].Value.(map[string]interface{})
		if !ok {
			log.Errorf("can't retrieve stored output for env %q", envName)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving stored output. Try updating the environment again to regenerate the output."})
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

			sendToSlackWebHook(
				fmt.Sprintf("Previewing environment %q on Domain %q...", envName, domain),
				slackWebHook,
			)

			var msg strings.Builder
			ctx := context.Background()

			inMemoryStore := bytes.NewBuffer([]byte{})
			gzipWriter, _ := gzip.NewWriterLevel(inMemoryStore, gzip.BestCompression)

			defer func() {
				gzipWriter.Close()

				if err := uploadLogs(ctx, inMemoryStore, envName, "preview", cfg, msg.String(), req.SlackWebHook, start); err != nil {
					log.Error(err)
				}
			}()

			_, err = s.Preview(ctx, optpreview.ProgressStreams(os.Stdout, gzipWriter))
			if err != nil {
				log.Errorf("preview env %q: %v", envName, err)
				msg.WriteString(fmt.Sprintf("Error occured while previewing environment %q", envName))
				return
			}

			success := fmt.Sprintf("Previewed environment %q on Domain %q in %s", envName, domain, time.Since(start))
			log.Infof(success)
			msg.WriteString(success)
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

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

			sendToSlackWebHook(
				fmt.Sprintf("Refreshing environment %q on Domain %q...", envName, domain),
				slackWebHook,
			)

			var msg strings.Builder
			ctx := context.Background()

			inMemoryStore := bytes.NewBuffer([]byte{})
			gzipWriter, _ := gzip.NewWriterLevel(inMemoryStore, gzip.BestCompression)

			defer func() {
				gzipWriter.Close()

				if err := uploadLogs(ctx, inMemoryStore, envName, "refresh", cfg, msg.String(), slackWebHook, start); err != nil {
					log.Error(err)
				}
			}()

			_, err = s.Refresh(ctx, optrefresh.ProgressStreams(os.Stdout, gzipWriter))
			if err != nil {
				log.Errorf("refresh env %q: %v", envName, err)
				msg.WriteString(fmt.Sprintf("Error occured while refreshing environment %q", envName))
				return
			}

			success := fmt.Sprintf("Refreshed environment %q on Domain %q in %s", envName, domain, time.Since(start))
			log.Infof(success)
			msg.WriteString(success)
		}()

		c.JSON(http.StatusOK, gin.H{
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
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

			sendToSlackWebHook(
				fmt.Sprintf("Importing environment %q on Domain %q...", envName, domain),
				slackWebHook,
			)

			marshalledStack, err := json.Marshal(req)
			if err != nil {
				log.Errorf("marshal stack env %q: %v", envName, err)
				sendToSlackWebHook(fmt.Sprintf("Error occured while marshalling stack environment %q", envName), slackWebHook)
				return
			}

			deployment := apitype.UntypedDeployment{
				Version:    3,
				Deployment: marshalledStack,
			}

			if err := s.Import(context.Background(), deployment); err != nil {
				log.Errorf("import env %q: %v", envName, err)
				sendToSlackWebHook(fmt.Sprintf("Error occured while importing environment %q", envName), slackWebHook)
				return
			}

			msg := fmt.Sprintf("Imported environment %q on Domain %q in %s", envName, domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook(msg, slackWebHook)
		}()

		c.JSON(http.StatusOK, gin.H{
			"result": fmt.Sprintf("environment %q is being imported", envName),
		})
	}
}

func updateEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		environment
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := req.environment.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		req.environment.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(req.environment), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		go func() {
			start := time.Now()

			sendToSlackWebHook(
				fmt.Sprintf("Updating environment %q with %v services on Domain %q...", envName, len(req.RsbServices.Services), req.AwsServices.Route53.Domain),
				req.SlackWebHook,
			)

			var msg strings.Builder
			ctx := context.Background()

			inMemoryStore := bytes.NewBuffer([]byte{})
			gzipWriter, _ := gzip.NewWriterLevel(inMemoryStore, gzip.BestCompression)

			defer func() {
				gzipWriter.Close()

				if err := uploadLogs(ctx, inMemoryStore, envName, "update", cfg, msg.String(), req.SlackWebHook, start); err != nil {
					log.Error(err)
				}
			}()

			_, err = s.Up(ctx, optup.ProgressStreams(os.Stdout, gzipWriter))
			if err != nil {
				if auto.IsConcurrentUpdateError(err) {
					msg.WriteString(fmt.Sprintf("Environment %q already has update in progress", envName))
					return
				}

				log.Errorf("update env %q: %v", envName, err)
				msg.WriteString(fmt.Sprintf("\nError occured while updating environment %q", envName))
				return
			}

			success := fmt.Sprintf("Updated environment %q with %v services on Domain %q in %s", envName, len(req.RsbServices.Services), req.AwsServices.Route53.Domain, time.Since(start))
			log.Infof(success)
			msg.WriteString(success)
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

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}), opts...)
		if err != nil {
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Used for s3 backend storage for stack
		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: cfg.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: cfg.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: cfg.AWSRegion})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

			sendToSlackWebHook(
				fmt.Sprintf("Deleting environment %q on Domain %q...", envName, domain),
				slackWebHook,
			)

			var msg strings.Builder
			ctx := context.Background()

			inMemoryStore := bytes.NewBuffer([]byte{})
			gzipWriter, _ := gzip.NewWriterLevel(inMemoryStore, gzip.BestCompression)

			defer func() {
				gzipWriter.Close()

				if err := uploadLogs(ctx, inMemoryStore, envName, "delete", cfg, msg.String(), slackWebHook, start); err != nil {
					log.Error(err)
				}
			}()

			if _, err := s.Destroy(ctx, optdestroy.ProgressStreams(os.Stdout, gzipWriter)); err != nil {
				log.Errorf("destroy env %q: %v", envName, err)
				msg.WriteString(fmt.Sprintf("Error occured while deleting environment %q", envName))
				return
			}

			if err = s.Workspace().RemoveStack(ctx, envName); err != nil {
				log.Errorf("remove stack env %q: %v", envName, err)
				msg.WriteString(fmt.Sprintf("Error occured while removing stack for environment %q", envName))
				return
			}

			success := fmt.Sprintf("Deleted environment %q on Domain %q in %s", envName, domain, time.Since(start))
			log.Infof(success)
			msg.WriteString(success)
		}()

		c.JSON(http.StatusOK, gin.H{
			"result": fmt.Sprintf("environment %q is being deleted", envName),
		})
	}
}
