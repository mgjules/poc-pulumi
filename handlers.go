package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optdestroy"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optup"
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
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}

		if err := req.environment.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
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
				c.JSON(http.StatusConflict, gin.H{"msg": fmt.Sprintf("environment %q already exists", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: req.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: req.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: req.AWSRegion})
		_ = s.SetConfig(ctx, "github:owner", auto.ConfigValue{Value: req.GithubOrgName})
		_ = s.SetConfig(ctx, "github:token", auto.ConfigValue{Value: req.GithubAuthToken, Secret: true})

		go func() {
			start := time.Now()

			res, err := s.Up(context.Background(), optup.ProgressStreams(os.Stdout))
			if err != nil {
				// c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while creating environment %q", envName)), req.SlackWebHook)
				return
			}

			msg := fmt.Sprintf("Created environment %q with %v services on Domain %s in %s", envName, len(req.RsbServices), req.Domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook([]byte(msg), req.SlackWebHook)

			result := res.Outputs["result"].Value.(map[string]interface{})
			sendToSlackWebHook([]byte(createOverview(result)), req.SlackWebHook)
		}()

		c.JSON(http.StatusCreated, gin.H{
			"result": fmt.Sprintf("environment %q is being created", envName),
		})
	}
}

func getEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		credentials
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}

		req.credentials.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}, credentials{}), opts...)
		if err != nil {
			// if stack doesn't already exist, 404
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"msg": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: req.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: req.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: req.AWSRegion})
		_ = s.SetConfig(ctx, "github:owner", auto.ConfigValue{Value: req.GithubOrgName})
		_ = s.SetConfig(ctx, "github:token", auto.ConfigValue{Value: req.GithubAuthToken, Secret: true})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"result": outs["result"].Value,
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
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}

		if err := req.environment.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
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
				c.JSON(http.StatusNotFound, gin.H{"msg": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: req.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: req.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: req.AWSRegion})
		_ = s.SetConfig(ctx, "github:owner", auto.ConfigValue{Value: req.GithubOrgName})
		_ = s.SetConfig(ctx, "github:token", auto.ConfigValue{Value: req.GithubAuthToken, Secret: true})

		go func() {
			start := time.Now()

			_, err = s.Up(context.Background() /*optup.Diff(),*/, optup.ProgressStreams(os.Stdout))
			if err != nil {
				if auto.IsConcurrentUpdateError(err) {
					// c.JSON(http.StatusConflict, gin.H{"msg": fmt.Sprintf("environment %q already has update in progress", envName)})
					sendToSlackWebHook([]byte(fmt.Sprintf("Environment %q already has update in progress", envName)), req.SlackWebHook)
					return
				}

				// c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while updating environment %q", envName)), req.SlackWebHook)
				return
			}

			msg := fmt.Sprintf("Updated environment %q with %v services on Domain %q in %s", envName, len(req.RsbServices), req.Domain, time.Since(start))
			log.Infof(msg)
			sendToSlackWebHook([]byte(msg), req.SlackWebHook)

			// Too noisy?
			// result := res.Outputs["result"].Value.(map[string]interface{})
			// sendToSlackWebHook([]byte(createOverview(result)), req.SlackWebHook)
		}()

		c.JSON(http.StatusCreated, gin.H{
			"result": fmt.Sprintf("environment %q is being updated", envName),
		})
	}
}

func deleteEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		credentials
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}

		req.credentials.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}, credentials{}), opts...)
		if err != nil {
			if auto.IsSelectStack404Error(err) {
				c.JSON(http.StatusNotFound, gin.H{"msg": fmt.Sprintf("environment %q not found", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		_ = s.SetConfig(ctx, "aws:accessKey", auto.ConfigValue{Value: req.AWSAccessKeyID, Secret: true})
		_ = s.SetConfig(ctx, "aws:secretKey", auto.ConfigValue{Value: req.AWSSecretAccessKey, Secret: true})
		_ = s.SetConfig(ctx, "aws:region", auto.ConfigValue{Value: req.AWSRegion})
		_ = s.SetConfig(ctx, "github:owner", auto.ConfigValue{Value: req.GithubOrgName})
		_ = s.SetConfig(ctx, "github:token", auto.ConfigValue{Value: req.GithubAuthToken, Secret: true})

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		result := outs["result"].Value.(map[string]interface{})
		slackWebHook := result["slack_webhook"].(string)
		domain := result["domain"].(string)

		go func() {
			start := time.Now()

			ctx := context.Background()

			if _, err := s.Destroy(ctx, optdestroy.ProgressStreams(os.Stdout)); err != nil {
				// 	c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
				sendToSlackWebHook([]byte(fmt.Sprintf("Error occured while deleting environment %q", envName)), slackWebHook)
				return
			}

			if err = s.Workspace().RemoveStack(ctx, envName); err != nil {
				// c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
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
