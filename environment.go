package main

import (
	"errors"
	"regexp"
)

type environment struct {
	Name                   string       `json:"name" binding:"required"`
	Domain                 string       `json:"domain"`
	DNSZoneID              string       `json:"dns_zone_id"`
	SlackWebHook           string       `json:"slack_webhook"`
	EcsVolumeSize          int          `json:"ecs_volume_size"`
	EcsCPU                 int          `json:"ecs_cpu"`
	EcsMemory              int          `json:"ecs_memory"`
	BastionAMIID           string       `json:"bastion_ami_id"`
	BrokerDriver           string       `json:"broker_driver"`
	ServicesCORSOriginURLs string       `json:"services_cors_origin_urls"`
	RsbServices            []RsbService `json:"rsb_services"`
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

	if e.BastionAMIID == "" {
		e.BastionAMIID = "ami-08bac620dc84221eb"
	}

	if e.BrokerDriver == "" {
		e.BrokerDriver = "rabbitmq"
	}

	if e.ServicesCORSOriginURLs == "" {
		e.ServicesCORSOriginURLs = "http://localhost:8080"
	}

	if len(e.RsbServices) == 0 {
		e.RsbServices = []RsbService{
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
		for i, rsbService := range e.RsbServices {
			if rsbService.SourceBranch == "" {
				e.RsbServices[i].SourceBranch = "develop"
			}
		}
	}
}
