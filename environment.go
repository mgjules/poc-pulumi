package main

import (
	"errors"
	"fmt"
	"regexp"
)

type environment struct {
	Name               string             `json:"name"`
	AWSAccessKeyID     string             `json:"aws_access_key_id"`
	AWSSecretAccessKey string             `json:"aws_secret_access_key"`
	AWSRegion          string             `json:"aws_region"`
	GithubAuthToken    string             `json:"github_auth_token"`
	GithubOrgName      string             `json:"github_org_name"`
	DockerHubUsername  string             `json:"dockerhub_username"`
	DockerHubPassword  string             `json:"dockerhub_password"`
	SlackWebHook       string             `json:"slack_webhook"`
	AwsServices        AwsServices        `json:"aws_services"`
	RsbServices        RsbServices        `json:"rsb_services"`
	ThirdPartyServices ThirdPartyServices `json:"third_party_services"`
}

func (e environment) Validate() error {
	if ok, err := regexp.MatchString(`^[a-z]{1,8}$`, e.Name); !ok || err != nil {
		return errors.New("environment name must be 1-8 all lower case characters")
	}

	return nil
}

func (e *environment) SetDefaults(cfg config) {
	if e.AWSAccessKeyID == "" {
		e.AWSAccessKeyID = cfg.AWSAccessKeyID
	}

	if e.AWSSecretAccessKey == "" {
		e.AWSSecretAccessKey = cfg.AWSSecretAccessKey
	}

	if e.AWSRegion == "" {
		e.AWSRegion = "eu-west-1"
	}

	if e.GithubAuthToken == "" {
		e.GithubAuthToken = cfg.GithubAuthToken
	}

	if e.GithubOrgName == "" {
		e.GithubOrgName = cfg.GithubOrgName
	}

	if e.AwsServices.Route53.Domain == "" {
		e.AwsServices.Route53.Domain = cfg.DNSDomain
	}

	if e.AwsServices.Route53.DNSZoneID == "" {
		e.AwsServices.Route53.DNSZoneID = cfg.DNSZoneID
	}

	if e.AwsServices.ES.Version == "" {
		e.AwsServices.ES.Version = "7.10"
	}

	if e.AwsServices.ECS.VolumeSize == 0 {
		e.AwsServices.ECS.VolumeSize = 32
	}

	if e.AwsServices.ECS.CPU == 0 {
		e.AwsServices.ECS.CPU = 256
	}

	if e.AwsServices.ECS.Memory == 0 {
		e.AwsServices.ECS.Memory = 512
	}

	if e.AwsServices.Bastion.AMIID == "" {
		e.AwsServices.Bastion.AMIID = "ami-08bac620dc84221eb"
	}

	if e.AwsServices.Bastion.VolumeSize == 0 {
		e.AwsServices.Bastion.VolumeSize = 32
	}

	if e.AwsServices.RDS.Username == "" {
		e.AwsServices.RDS.Username = "admin"
	}

	if e.AwsServices.Codebuild.Image == "" {
		e.AwsServices.Codebuild.Image = "aws/codebuild/standard:5.0"
	}

	if e.RsbServices.CORSOriginURLs == "" {
		e.RsbServices.CORSOriginURLs = "http://localhost:8080"
	}

	if e.RsbServices.Broker.Driver == "" {
		e.RsbServices.Broker.Driver = "rabbitmq"
	}

	if e.RsbServices.Broker.Username == "" {
		e.RsbServices.Broker.Username = "admin"
	}

	if e.RsbServices.Broker.Port == 0 {
		e.RsbServices.Broker.Port = 5672
	}

	if e.RsbServices.Broker.AdminPort == 0 {
		e.RsbServices.Broker.AdminPort = 15672
	}

	rsbServiceNames := map[string]struct{}{}
	for i, rsbService := range e.RsbServices.Services {
		rsbServiceNames[rsbService.Name] = struct{}{}

		if rsbService.SourceBranch == "" && rsbService.SourceCommit == "" {
			e.RsbServices.Services[i].SourceBranch = "develop"
		}

		if rsbService.Count > 3 {
			rsbService.Count = 3
		} else if rsbService.Count < 0 {
			rsbService.Count = 0
		}
	}

	// Don't even think of running the bus without the services below
	for _, rsbCoreServiceName := range []string{
		"rsb-service-feeder",
		"rsb-service-worker",
		"rsb-service-ventureconfig",
		"rsb-service-servicerepository",
		"rsb-service-users",
	} {
		if _, found := rsbServiceNames[rsbCoreServiceName]; !found {
			e.RsbServices.Services = append(e.RsbServices.Services, RsbService{
				Name:         rsbCoreServiceName,
				SourceBranch: "develop",
				Count:        1,
			})
		}
	}

	if e.ThirdPartyServices.CloudAMQP.InstanceName == "" {
		e.ThirdPartyServices.CloudAMQP.InstanceName = e.Name
	}

	switch e.ThirdPartyServices.CloudAMQP.InstanceType {
	case "bunny", "rabbit", "panda", "ape", "hippo", "lion", "toad":
		// all good
	default:
		e.ThirdPartyServices.CloudAMQP.InstanceType = "bunny"
	}

	if e.ThirdPartyServices.CloudAMQP.InstanceType == "bunny" && e.ThirdPartyServices.CloudAMQP.InstanceNodes != 1 {
		e.ThirdPartyServices.CloudAMQP.InstanceNodes = 1
	}

	if e.ThirdPartyServices.CloudAMQP.InstanceRegion == "" {
		e.ThirdPartyServices.CloudAMQP.InstanceRegion = fmt.Sprintf("amazon-web-services::%s", e.AWSRegion)
	}

	if e.ThirdPartyServices.CloudAMQP.InstanceSubnet == "" {
		e.ThirdPartyServices.CloudAMQP.InstanceSubnet = "10.56.72.0/24"
	}
}
