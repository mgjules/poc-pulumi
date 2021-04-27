package main

import (
	"encoding/base64"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/acm"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/resourcegroups"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/route53"
	"github.com/pulumi/pulumi-random/sdk/v4/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	_vpcCIDR = "10.15.96.0/19"
)

var (
	_subnets = []struct {
		Group  string
		CIDR   string
		AZ     string
		Public bool
	}{
		// Public
		{Group: "public", CIDR: "10.15.111.0/24", AZ: "eu-west-1a", Public: true},
		{Group: "public", CIDR: "10.15.112.0/24", AZ: "eu-west-1b", Public: true},
		{Group: "public", CIDR: "10.15.113.0/24", AZ: "eu-west-1c", Public: true},
		// Private
		{Group: "private", CIDR: "10.15.96.0/24", AZ: "eu-west-1a", Public: false},
		{Group: "private", CIDR: "10.15.97.0/24", AZ: "eu-west-1b", Public: false},
		{Group: "private", CIDR: "10.15.98.0/24", AZ: "eu-west-1c", Public: false},
		// Database
		{Group: "database", CIDR: "10.15.101.0/24", AZ: "eu-west-1a", Public: false},
		{Group: "database", CIDR: "10.15.102.0/24", AZ: "eu-west-1b", Public: false},
		{Group: "database", CIDR: "10.15.103.0/24", AZ: "eu-west-1c", Public: false},
		// ElasticCache
		{Group: "elasticcache", CIDR: "10.15.106.0/24", AZ: "eu-west-1a", Public: false},
		{Group: "elasticcache", CIDR: "10.15.107.0/24", AZ: "eu-west-1b", Public: false},
		{Group: "elasticcache", CIDR: "10.15.108.0/24", AZ: "eu-west-1c", Public: false},
	}
)

func infra(env environment) pulumi.RunFunc {
	return func(ctx *pulumi.Context) error {
		// Tags
		tags := pulumi.ToStringMap(map[string]string{
			"RSB_ENV": env.Name,
			"Name":    env.Name,
		})

		// Resource Group
		_, err := resourcegroups.NewGroup(ctx, "rg-"+env.Name, &resourcegroups.GroupArgs{
			Name:        pulumi.String(env.Name),
			Description: pulumi.String("Everything tagged " + env.Name),
			ResourceQuery: &resourcegroups.GroupResourceQueryArgs{
				Query: pulumi.Sprintf("{\"ResourceTypeFilters\": [\"AWS::AllSupported\"], \"TagFilters\": [{\"Key\": \"RSB_ENV\", \"Values\": [\"%s\"]}]}", env.Name),
			},
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating resource group: %w", err)
		}

		// TODO: might need to create a s3 backup bucket (see miscUp)

		// VPC
		vpc, err := ec2.NewVpc(ctx, "vpc-"+env.Name, &ec2.VpcArgs{
			CidrBlock:                    pulumi.String(_vpcCIDR),
			AssignGeneratedIpv6CidrBlock: pulumi.Bool(true),
			Tags:                         tags,
		})
		if err != nil {
			return fmt.Errorf("creating vpc: %w", err)
		}

		// Subnets
		subnetGroups := make(map[string][]*ec2.Subnet)
		for i, subnet := range _subnets {
			name := fmt.Sprintf("subnet-%s-%s-%d", env.Name, subnet.Group, i)
			sbnt, err := ec2.NewSubnet(ctx, name, &ec2.SubnetArgs{
				CidrBlock:           pulumi.String(subnet.CIDR),
				AvailabilityZone:    pulumi.String(subnet.AZ),
				MapPublicIpOnLaunch: pulumi.Bool(subnet.Public),
				VpcId:               vpc.ID(),
				Tags:                tags,
			})
			if err != nil {
				return fmt.Errorf("creating vpc subnet [%s]: %w", name, err)
			}

			subnetGroups[subnet.Group] = append(subnetGroups[subnet.Group], sbnt)
		}

		// Internet Gateway
		igw, err := ec2.NewInternetGateway(ctx, "igw-"+env.Name, &ec2.InternetGatewayArgs{
			VpcId: vpc.ID(),
			Tags:  tags,
		})
		if err != nil {
			return fmt.Errorf("creating internet gateway: %w", err)
		}

		// Elastic IP
		eip, err := ec2.NewEip(ctx, "eip-"+env.Name, &ec2.EipArgs{
			Tags: tags,
		}, pulumi.DependsOn([]pulumi.Resource{igw}))
		if err != nil {
			return fmt.Errorf("creating elastic ip: %w", err)
		}

		// NAT Gateway
		nat, err := ec2.NewNatGateway(ctx, "nat-"+env.Name, &ec2.NatGatewayArgs{
			AllocationId: eip.ID(),
			SubnetId:     subnetGroups["public"][0].ID(),
			Tags:         tags,
		})
		if err != nil {
			return fmt.Errorf("creating internet gateway: %w", err)
		}

		// Route tables
		routeTables := make(map[string]*ec2.RouteTable)
		for groupName, subnets := range subnetGroups {
			routeTableName := "rt-" + env.Name + "-" + groupName
			rt, err := ec2.NewRouteTable(ctx, routeTableName, &ec2.RouteTableArgs{
				VpcId: vpc.ID(),
				Tags:  tags,
			})
			if err != nil {
				return fmt.Errorf("creating route table [%s]: %w", routeTableName, err)
			}

			routeTables[routeTableName] = rt

			// Default Route
			routeArgs := &ec2.RouteArgs{
				RouteTableId:         rt.ID(),
				DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
			}

			if groupName == "public" {
				routeArgs.GatewayId = igw.ID()
			} else {
				routeArgs.NatGatewayId = nat.ID()
			}

			routeName := "route-default-" + env.Name + "-" + groupName
			_, err = ec2.NewRoute(ctx, routeName, routeArgs)
			if err != nil {
				return fmt.Errorf("creating default route [%s]: %w", routeName, err)
			}

			// Route table assiociations
			for i, subnet := range subnets {
				routeAssocName := fmt.Sprintf("rt-assoc-%s-%s-%d", env.Name, groupName, i)
				_, err = ec2.NewRouteTableAssociation(ctx, routeAssocName, &ec2.RouteTableAssociationArgs{
					RouteTableId: rt.ID(),
					SubnetId:     subnet.ID(),
				})
				if err != nil {
					return fmt.Errorf("creating route table assiociation [%s]: %w", routeAssocName, err)
				}
			}
		}

		// Security Group
		sg, err := ec2.NewSecurityGroup(ctx, "sg-"+env.Name, &ec2.SecurityGroupArgs{
			Name:        pulumi.Sprintf("%s-main", env.Name),
			Description: pulumi.Sprintf("Main security group for %s", env.Name),
			VpcId:       vpc.ID(),
			Egress: ec2.SecurityGroupEgressArray{
				// Allow outbound traffic to any
				ec2.SecurityGroupEgressArgs{
					Protocol: pulumi.String("all"),
					FromPort: pulumi.Int(0),
					ToPort:   pulumi.Int(0),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
					Ipv6CidrBlocks: pulumi.StringArray{
						pulumi.String("::/0"),
					},
				},
			},
			Ingress: ec2.SecurityGroupIngressArray{
				// Open HTTPS and SSH to public
				ec2.SecurityGroupIngressArgs{
					Protocol:    pulumi.String("tcp"),
					FromPort:    pulumi.Int(22),
					ToPort:      pulumi.Int(22),
					Description: pulumi.String("SSH"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				ec2.SecurityGroupIngressArgs{
					Protocol:    pulumi.String("tcp"),
					FromPort:    pulumi.Int(443),
					ToPort:      pulumi.Int(443),
					Description: pulumi.String("HTTPS"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				// Open the wireguard VPN port
				ec2.SecurityGroupIngressArgs{
					Protocol:    pulumi.String("udp"),
					FromPort:    pulumi.Int(51820),
					ToPort:      pulumi.Int(51820),
					Description: pulumi.String("Wireguard VPN"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				// Open to Ringier VPN
				ec2.SecurityGroupIngressArgs{
					Protocol:    pulumi.String("all"),
					FromPort:    pulumi.Int(0),
					ToPort:      pulumi.Int(0),
					Description: pulumi.String("Ringier VPN"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("108.128.7.94/32"),
					},
				},
				// Allow connections from internal (Fargate)
				ec2.SecurityGroupIngressArgs{
					Protocol:    pulumi.String("all"),
					FromPort:    pulumi.Int(0),
					ToPort:      pulumi.Int(0),
					Description: pulumi.String("Internal Fargate"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("10.0.0.0/8"),
						pulumi.String("172.16.0.0/12"),
						pulumi.String("192.168.0.0/16"),
					},
				},
			},
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating security group: %w", err)
		}

		// Certificate for services
		certServices, err := acm.NewCertificate(ctx, "cert-services-"+env.Name, &acm.CertificateArgs{
			DomainName:       pulumi.Sprintf("*.services.%s.%s", env.Name, env.Domain),
			ValidationMethod: pulumi.String("DNS"),
			Tags:             tags,
		})
		if err != nil {
			return fmt.Errorf("creating cert for services: %w", err)
		}

		// Validation CNAME record for certificate services
		recordCertServices, err := route53.NewRecord(ctx, "record-cert-services-validation"+env.Name, &route53.RecordArgs{
			Name: certServices.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordName().Elem(),
			Type: certServices.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordType().Elem(),
			Records: pulumi.StringArray{
				certServices.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordValue().Elem(),
			},
			ZoneId: pulumi.String(env.DNSZoneID),
			Ttl:    pulumi.Int(300),
		})
		if err != nil {
			return fmt.Errorf("creating record for cert validation for services: %w", err)
		}

		// Request certificate validation for services
		_, err = acm.NewCertificateValidation(ctx, "cert-services-validation-"+env.Name, &acm.CertificateValidationArgs{
			CertificateArn: certServices.Arn,
			ValidationRecordFqdns: pulumi.StringArray{
				recordCertServices.Fqdn,
			},
		})
		if err != nil {
			return fmt.Errorf("creating cert validation for services: %w", err)
		}

		// Certificate for wildcard
		certWildcard, err := acm.NewCertificate(ctx, "cert-wildcard-"+env.Name, &acm.CertificateArgs{
			DomainName:       pulumi.Sprintf("*.%s.%s", env.Name, env.Domain),
			ValidationMethod: pulumi.String("DNS"),
			Tags:             tags,
		})
		if err != nil {
			return fmt.Errorf("creating cert for wildcard: %w", err)
		}

		// Validation CNAME record for certificate wildcard
		recordCertWildcard, err := route53.NewRecord(ctx, "record-cert-wildcard-validation"+env.Name, &route53.RecordArgs{
			Name: certWildcard.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordName().Elem(),
			Type: certWildcard.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordType().Elem(),
			Records: pulumi.StringArray{
				certWildcard.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordValue().Elem(),
			},
			ZoneId: pulumi.String(env.DNSZoneID),
			Ttl:    pulumi.Int(300),
		})
		if err != nil {
			return fmt.Errorf("creating record for cert validation for wildcard: %w", err)
		}

		// Request certificate validation for wildcard
		_, err = acm.NewCertificateValidation(ctx, "cert-wildcard-validation-"+env.Name, &acm.CertificateValidationArgs{
			CertificateArn: certWildcard.Arn,
			ValidationRecordFqdns: pulumi.StringArray{
				recordCertWildcard.Fqdn,
			},
		})
		if err != nil {
			return fmt.Errorf("creating cert validation for wildcard: %w", err)
		}

		dbMasterUserPassword, err := random.NewRandomPassword(ctx, "password-db-master-user-password-"+env.Name, &random.RandomPasswordArgs{
			Length:  pulumi.Int(32),
			Lower:   pulumi.Bool(true),
			Upper:   pulumi.Bool(true),
			Special: pulumi.Bool(false),
		})
		if err != nil {
			return fmt.Errorf("creating db master user password: %w", err)
		}

		if env.DBMasterUserPassword == "" {
			dbMasterUserPassword.Result.ApplyT(func(result string) string {
				env.DBMasterUserPassword = result
				return result
			})
		}

		rmqMasterUserPassword, err := random.NewRandomPassword(ctx, "password-rmq-master-user-password-"+env.Name, &random.RandomPasswordArgs{
			Length:  pulumi.Int(32),
			Lower:   pulumi.Bool(true),
			Upper:   pulumi.Bool(true),
			Special: pulumi.Bool(false),
		})
		if err != nil {
			return fmt.Errorf("creating rmq master user password: %w", err)
		}

		if env.RMQMasterUserPassword == "" {
			rmqMasterUserPassword.Result.ApplyT(func(result string) string {
				env.RMQMasterUserPassword = result
				return result
			})
		}

		// Bastion instance
		// FIXME: perpetual diff for EbsBlockDevices
		bastion, err := ec2.NewInstance(ctx, "ec2-instance-bastion-"+env.Name, &ec2.InstanceArgs{
			Ami:                               pulumi.String(env.BastionAMIID),
			InstanceType:                      pulumi.String("t3.micro"),
			SubnetId:                          subnetGroups["public"][0].ID(),
			SourceDestCheck:                   pulumi.Bool(false),
			InstanceInitiatedShutdownBehavior: pulumi.String("terminate"),
			EbsBlockDevices: &ec2.InstanceEbsBlockDeviceArray{
				&ec2.InstanceEbsBlockDeviceArgs{
					DeviceName: pulumi.String("/dev/sda1"),
					VolumeSize: pulumi.Int(env.EcsVolumeSize),
					Encrypted:  pulumi.Bool(false),
				},
			},
			VpcSecurityGroupIds: pulumi.StringArray{
				sg.ID(),
			},
			UserDataBase64: pulumi.String(
				base64.StdEncoding.EncodeToString(
					[]byte(fmt.Sprintf("#!/bin/bash\ncd /root\nprintf \"\\nmachine github.com\nlogin roam\npassword %s\" >> .netrc\ngit clone https://github.com/RingierIMU/rsb-deploy.git\necho -n \"%s\" > RMQMasterUserPassword\necho -n \"%s\" > DBMasterUserPassword\necho -n \"%s\" > RSB_Env\necho -n \"%s\" > SLACK_WEBHOOK\ncd ./rsb-deploy/aws/bastion/\n./setup.sh", env.GithubAuthToken, env.RMQMasterUserPassword, env.DBMasterUserPassword, env.Name, env.SlackWebHook)),
				),
			),
			VolumeTags: tags,
			Tags:       tags,
		}, pulumi.DependsOn([]pulumi.Resource{dbMasterUserPassword, rmqMasterUserPassword}))
		if err != nil {
			return fmt.Errorf("creating ec2 instance for bastion: %w", err)
		}

		// Public A record for bastion instance
		_, err = route53.NewRecord(ctx, "record-pub-bastion"+env.Name, &route53.RecordArgs{
			Name: pulumi.Sprintf("bastion.%s.%s", env.Name, env.Domain),
			Type: pulumi.String("A"),
			Records: pulumi.StringArray{
				bastion.PublicIp,
			},
			ZoneId: pulumi.String(env.DNSZoneID),
			Ttl:    pulumi.Int(300),
		})
		if err != nil {
			return fmt.Errorf("creating public A record for bastion: %w", err)
		}

		// Public A record for bastion instance
		_, err = route53.NewRecord(ctx, "record-priv-bastion"+env.Name, &route53.RecordArgs{
			Name: pulumi.Sprintf("srv.%s.%s", env.Name, env.Domain),
			Type: pulumi.String("A"),
			Records: pulumi.StringArray{
				bastion.PrivateIp,
			},
			ZoneId: pulumi.String(env.DNSZoneID),
			Ttl:    pulumi.Int(300),
		})
		if err != nil {
			return fmt.Errorf("creating private A record for bastion: %w", err)
		}

		// Routes for bastion instance
		for routeTableName, routeTable := range routeTables {
			routeName := fmt.Sprintf("route-bastion-%s-%s", env.Name, routeTableName)
			_, err = ec2.NewRoute(ctx, routeName, &ec2.RouteArgs{
				RouteTableId:         routeTable.ID(),
				InstanceId:           bastion.ID(),
				DestinationCidrBlock: pulumi.String("192.168.12.0/24"),
			})
			if err != nil {
				return fmt.Errorf("creating bastion route [%s]: %w", routeName, err)
			}
		}

		// TODO: implement current infra setup (mq+cache+ecs+fargate+apigw)

		ctx.Export("vpc", vpc.Arn)
		return nil
	}
}
