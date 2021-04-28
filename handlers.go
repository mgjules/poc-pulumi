package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optdestroy"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optup"
)

func createEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		environment
		awsCredentials
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

		req.awsCredentials.SetDefaults(cfg)
		req.environment.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := req.Name

		s, err := auto.NewStackInlineSource(ctx, envName, _projectName, infra(req.environment), opts...)
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

		res, err := s.Up(ctx, optup.ProgressStreams(os.Stdout))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"name": envName,
			"vpc":  res.Outputs["vpc"].Value,
		})
	}
}

func getEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		awsCredentials
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}

		req.awsCredentials.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}), opts...)
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

		outs, err := s.Outputs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"name": envName,
			"vpc":  outs["vpc"].Value,
		})
	}
}

func updateEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		environment
		awsCredentials
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

		req.awsCredentials.SetDefaults(cfg)
		req.environment.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(req.environment), opts...)
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

		res, err := s.Up(ctx /*optup.Diff(),*/, optup.ProgressStreams(os.Stdout))
		if err != nil {
			if auto.IsConcurrentUpdateError(err) {
				c.JSON(http.StatusConflict, gin.H{"msg": fmt.Sprintf("environment %q already has update in progress", envName)})
				return
			}

			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"name": envName,
			"vpc":  res.Outputs["vpc"].Value,
		})
	}
}

func deleteEnvironment(cfg config, opts ...auto.LocalWorkspaceOption) gin.HandlerFunc {
	type request struct {
		awsCredentials
	}

	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}

		req.awsCredentials.SetDefaults(cfg)

		ctx := c.Request.Context()
		envName := c.Param("name")

		s, err := auto.SelectStackInlineSource(ctx, envName, _projectName, infra(environment{}), opts...)
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

		if _, err = s.Destroy(ctx, optdestroy.ProgressStreams(os.Stdout)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		if err = s.Workspace().RemoveStack(ctx, envName); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"msg": fmt.Sprintf("environment %q deleted", envName),
		})
	}
}
