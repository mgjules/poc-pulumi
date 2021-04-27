package main

import (
	"errors"
	"regexp"
)

type environment struct {
	Name                  string `json:"name" binding:"required"`
	Domain                string `json:"domain"`
	DNSZoneID             string `json:"dns_zone_id"`
	SlackWebHook          string `json:"slack_webhook"`
	EcsVolumeSize         int    `json:"ecs_volume_size"`
	EcsCPU                int    `json:"ecs_cpu"`
	EcsMemory             int    `json:"ecs_memory"`
	SourceBranch          string `json:"source_branch"`
	GithubAuthToken       string `json:"github_auth_token"`
	GithubOrgName         string `json:"github_org_name"`
	ApiGatewayBaseDef     string `json:"api_gateway_base_definition"`
	BastionAMIID          string `json:"bastion_ami_id"`
	DBMasterUserPassword  string `json:"db_master_user_password"`
	RMQMasterUserPassword string `json:"rmq_master_user_password"`
}

func (e environment) Validate() error {
	if ok, err := regexp.MatchString(`^[a-z]{1,8}$`, e.Name); !ok || err != nil {
		return errors.New("environment name must be 1-8 all lower case characters")
	}

	return nil
}

func (e *environment) SetDefaults(cfg config) {
	if e.Domain == "" {
		e.Domain = cfg.DNSDomain
	}

	if e.DNSZoneID == "" {
		e.DNSZoneID = cfg.DNSZoneID
	}

	if e.EcsVolumeSize == 0 {
		e.EcsVolumeSize = 32
	}

	if e.EcsCPU == 0 {
		e.EcsCPU = 256
	}

	if e.EcsMemory == 0 {
		e.EcsMemory = 512
	}

	if e.SourceBranch == "" {
		e.SourceBranch = "develop"
	}

	if e.GithubAuthToken == "" {
		e.GithubAuthToken = cfg.GithubAuthToken
	}

	if e.GithubOrgName == "" {
		e.GithubOrgName = cfg.GithubOrgName
	}

	if e.ApiGatewayBaseDef == "" {
		e.ApiGatewayBaseDef = `{"swagger":"2.0","info":{"version":"1.0.0","title":"API TITLE"},"schemes":["https"],"paths":{"/events":{"post":{"produces":["application/json"],"responses":{"200":{"description":"200 response"},"500":{"description":"500 response"}},"x-amazon-apigateway-integration":{"uri":"https://www.zebroc.de/h00k/","responses":{"default":{"statusCode":"200"}},"passthroughBehavior":"when_no_match","httpMethod":"POST","type":"http"}}},"/login":{"post":{"responses":{"200":{"description":"200 response"},"400":{"description":"400 response"},"500":{"description":"500 response"},"401":{"description":"401 response"},"404":{"description":"404 response"}},"x-amazon-apigateway-integration":{"uri":"https://www.zebroc.de/h00k/","responses":{"200":{"statusCode":"200"},"400":{"statusCode":"400"},"500":{"statusCode":"500"},"401":{"statusCode":"401"},"404":{"statusCode":"404"}},"passthroughBehavior":"when_no_match","httpMethod":"POST","type":"http"}}}},"securityDefinitions":{"api_key":{"type":"apiKey","name":"x-api-key","in":"header"}}}`
	}

	if e.BastionAMIID == "" {
		e.BastionAMIID = "ami-0aef57767f5404a3c"
	}
}
