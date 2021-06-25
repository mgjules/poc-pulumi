package main

import (
	"errors"
	"regexp"
)

type environment struct {
	Name               string             `json:"name" binding:"required"`
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

	if e.AwsServices.RDS.Username == "" {
		e.AwsServices.RDS.Username = "admin"
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

	if len(e.RsbServices.Services) == 0 {
		e.RsbServices.Services = []RsbService{
			{
				Name:         "rsb-service-feeder",
				SourceBranch: "develop",
			},
			{
				Name:         "rsb-service-worker",
				SourceBranch: "develop",
			},
			{
				Name:         "rsb-service-ventureconfig",
				SourceBranch: "develop",
			},
			{
				Name:         "rsb-service-servicerepository",
				SourceBranch: "develop",
			},
			{
				Name:         "rsb-service-users",
				SourceBranch: "develop",
			},
		}
	} else {
		for i, rsbService := range e.RsbServices.Services {
			if rsbService.SourceBranch == "" {
				e.RsbServices.Services[i].SourceBranch = "develop"
			}
		}
	}
}
