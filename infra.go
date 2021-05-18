package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/acm"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/apigateway"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/codebuild"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/codepipeline"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ecr"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ecs"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/elasticache"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/elasticloadbalancingv2"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/resourcegroups"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/route53"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/s3"
	"github.com/pulumi/pulumi-github/sdk/v4/go/github"
	"github.com/pulumi/pulumi-random/sdk/v4/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	_subnetGroupPublic       = "public"
	_subnetGroupPrivate      = "private"
	_subnetGroupDatabase     = "database"
	_subnetGroupElasticCache = "elasticcache"
)

var (
	_subnets = []struct {
		Group  string
		CIDR   string
		AZ     string
		Public bool
	}{
		// Public
		{Group: _subnetGroupPublic, CIDR: "10.15.111.0/24", AZ: "eu-west-1a", Public: true},
		{Group: _subnetGroupPublic, CIDR: "10.15.112.0/24", AZ: "eu-west-1b", Public: true},
		{Group: _subnetGroupPublic, CIDR: "10.15.113.0/24", AZ: "eu-west-1c", Public: true},
		// Private
		{Group: _subnetGroupPrivate, CIDR: "10.15.96.0/24", AZ: "eu-west-1a", Public: false},
		{Group: _subnetGroupPrivate, CIDR: "10.15.97.0/24", AZ: "eu-west-1b", Public: false},
		{Group: _subnetGroupPrivate, CIDR: "10.15.98.0/24", AZ: "eu-west-1c", Public: false},
		// Database
		{Group: _subnetGroupDatabase, CIDR: "10.15.101.0/24", AZ: "eu-west-1a", Public: false},
		{Group: _subnetGroupDatabase, CIDR: "10.15.102.0/24", AZ: "eu-west-1b", Public: false},
		{Group: _subnetGroupDatabase, CIDR: "10.15.103.0/24", AZ: "eu-west-1c", Public: false},
		// ElasticCache
		{Group: _subnetGroupElasticCache, CIDR: "10.15.106.0/24", AZ: "eu-west-1a", Public: false},
		{Group: _subnetGroupElasticCache, CIDR: "10.15.107.0/24", AZ: "eu-west-1b", Public: false},
		{Group: _subnetGroupElasticCache, CIDR: "10.15.108.0/24", AZ: "eu-west-1c", Public: false},
	}

	_apiGWServices = map[string]bool{"rsb-service-users": true, "rsb-service-feeder": true}
)

func infra(env environment, cred credentials) pulumi.RunFunc {
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
			CidrBlock:                    pulumi.String("10.15.96.0/19"),
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
			}, pulumi.Parent(vpc))
			if err != nil {
				return fmt.Errorf("creating vpc subnet [%s]: %w", name, err)
			}

			subnetGroups[subnet.Group] = append(subnetGroups[subnet.Group], sbnt)
		}

		// Internet Gateway
		igw, err := ec2.NewInternetGateway(ctx, "igw-"+env.Name, &ec2.InternetGatewayArgs{
			VpcId: vpc.ID(),
			Tags:  tags,
		}, pulumi.Parent(vpc))
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
			SubnetId:     subnetGroups[_subnetGroupPublic][0].ID(),
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
			}, pulumi.Parent(vpc))
			if err != nil {
				return fmt.Errorf("creating route table [%s]: %w", routeTableName, err)
			}

			routeTables[routeTableName] = rt

			// Default Route
			routeArgs := &ec2.RouteArgs{
				RouteTableId:         rt.ID(),
				DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
			}

			if groupName == _subnetGroupPublic {
				routeArgs.GatewayId = igw.ID()
			} else {
				routeArgs.NatGatewayId = nat.ID()
			}

			routeName := "route-default-" + env.Name + "-" + groupName
			_, err = ec2.NewRoute(ctx, routeName, routeArgs, pulumi.Parent(rt))
			if err != nil {
				return fmt.Errorf("creating default route [%s]: %w", routeName, err)
			}

			// Route table assiociations
			for i, subnet := range subnets {
				routeAssocName := fmt.Sprintf("rt-assoc-%s-%s-%d", env.Name, groupName, i)
				_, err = ec2.NewRouteTableAssociation(ctx, routeAssocName, &ec2.RouteTableAssociationArgs{
					RouteTableId: rt.ID(),
					SubnetId:     subnet.ID(),
				}, pulumi.Parent(rt))
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
					Protocol: ec2.ProtocolTypeAll,
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
					Protocol:    ec2.ProtocolTypeTCP,
					FromPort:    pulumi.Int(22),
					ToPort:      pulumi.Int(22),
					Description: pulumi.String("SSH"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				ec2.SecurityGroupIngressArgs{
					Protocol:    ec2.ProtocolTypeTCP,
					FromPort:    pulumi.Int(443),
					ToPort:      pulumi.Int(443),
					Description: pulumi.String("HTTPS"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				// Open the wireguard VPN port
				ec2.SecurityGroupIngressArgs{
					Protocol:    ec2.ProtocolTypeUDP,
					FromPort:    pulumi.Int(51820),
					ToPort:      pulumi.Int(51820),
					Description: pulumi.String("Wireguard VPN"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				// Open to Ringier VPN
				ec2.SecurityGroupIngressArgs{
					Protocol:    ec2.ProtocolTypeAll,
					FromPort:    pulumi.Int(0),
					ToPort:      pulumi.Int(0),
					Description: pulumi.String("Ringier VPN"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("108.128.7.94/32"),
					},
				},
				// Allow connections from internal (Fargate)
				ec2.SecurityGroupIngressArgs{
					Protocol:    ec2.ProtocolTypeAll,
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
		}, pulumi.Parent(vpc))
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
		}, pulumi.Parent(certServices))
		if err != nil {
			return fmt.Errorf("creating record for cert validation for services: %w", err)
		}

		// Request certificate validation for services
		_, err = acm.NewCertificateValidation(ctx, "cert-services-validation-"+env.Name, &acm.CertificateValidationArgs{
			CertificateArn: certServices.Arn,
			ValidationRecordFqdns: pulumi.StringArray{
				recordCertServices.Fqdn,
			},
		}, pulumi.Parent(certServices))
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
		}, pulumi.Parent(certWildcard))
		if err != nil {
			return fmt.Errorf("creating record for cert validation for wildcard: %w", err)
		}

		// Request certificate validation for wildcard
		certValidationWildcard, err := acm.NewCertificateValidation(ctx, "cert-wildcard-validation-"+env.Name, &acm.CertificateValidationArgs{
			CertificateArn: certWildcard.Arn,
			ValidationRecordFqdns: pulumi.StringArray{
				recordCertWildcard.Fqdn,
			},
		}, pulumi.Parent(certWildcard))
		if err != nil {
			return fmt.Errorf("creating cert validation for wildcard: %w", err)
		}

		dbMasterUserPasswordGenerated, err := random.NewRandomPassword(ctx, "password-db-master-user-password-"+env.Name, &random.RandomPasswordArgs{
			Length:  pulumi.Int(32),
			Lower:   pulumi.Bool(true),
			Upper:   pulumi.Bool(true),
			Special: pulumi.Bool(false),
		})
		if err != nil {
			return fmt.Errorf("creating db master user password: %w", err)
		}

		dbMasterUserPassword := dbMasterUserPasswordGenerated.Result.ApplyT(func(result string) string {
			if cred.DBMasterUserPassword != "" {
				return cred.DBMasterUserPassword
			}
			return result
		}).(pulumi.StringOutput)

		rmqMasterUserPasswordGenerated, err := random.NewRandomPassword(ctx, "password-rmq-master-user-password-"+env.Name, &random.RandomPasswordArgs{
			Length:  pulumi.Int(32),
			Lower:   pulumi.Bool(true),
			Upper:   pulumi.Bool(true),
			Special: pulumi.Bool(false),
		})
		if err != nil {
			return fmt.Errorf("creating rmq master user password: %w", err)
		}

		rmqMasterUserPassword := rmqMasterUserPasswordGenerated.Result.ApplyT(func(result string) string {
			if cred.RMQMasterUserPassword != "" {
				return cred.RMQMasterUserPassword
			}
			return result
		}).(pulumi.StringOutput)

		UserDataBase64 := pulumi.All(dbMasterUserPassword, rmqMasterUserPassword).ApplyT(func(args []interface{}) string {
			return base64.StdEncoding.EncodeToString(
				[]byte(fmt.Sprintf("#!/bin/bash\ncd /root\nprintf \"\\nmachine github.com\nlogin roam\npassword %s\" >> .netrc\ngit clone https://github.com/RingierIMU/rsb-deploy.git\necho -n \"%s\" > RMQMasterUserPassword\necho -n \"%s\" > DBMasterUserPassword\necho -n \"%s\" > RSB_Env\necho -n \"%s\" > SLACK_WEBHOOK\ncd ./rsb-deploy/aws/bastion/\n./setup.sh", cred.GithubAuthToken, args[1].(string), args[0].(string), env.Name, env.SlackWebHook)),
			)
		}).(pulumi.StringOutput)

		// Bastion instance
		// NOTE: perpetual diff for EbsBlockDevices so using default with AMI
		bastion, err := ec2.NewInstance(ctx, "ec2-instance-bastion-"+env.Name, &ec2.InstanceArgs{
			Ami:             pulumi.String(env.BastionAMIID),
			InstanceType:    ec2.InstanceType_T3_Micro,
			SubnetId:        subnetGroups[_subnetGroupPublic][0].ID(),
			SourceDestCheck: pulumi.Bool(false),
			VpcSecurityGroupIds: pulumi.StringArray{
				sg.ID(),
			},
			UserDataBase64: UserDataBase64,
			VolumeTags:     tags,
			Tags:           tags,
		})
		if err != nil {
			return fmt.Errorf("creating ec2 instance for bastion: %w", err)
		}

		// Public A record for bastion instance
		_, err = route53.NewRecord(ctx, "record-pub-bastion"+env.Name, &route53.RecordArgs{
			Name: pulumi.Sprintf("bastion.%s.%s", env.Name, env.Domain),
			Type: route53.RecordTypeA,
			Records: pulumi.StringArray{
				bastion.PublicIp,
			},
			ZoneId: pulumi.String(env.DNSZoneID),
			Ttl:    pulumi.Int(300),
		}, pulumi.Parent(bastion))
		if err != nil {
			return fmt.Errorf("creating public A record for bastion: %w", err)
		}

		// Private A record for bastion instance
		_, err = route53.NewRecord(ctx, "record-priv-bastion"+env.Name, &route53.RecordArgs{
			Name: pulumi.Sprintf("srv.%s.%s", env.Name, env.Domain),
			Type: route53.RecordTypeA,
			Records: pulumi.StringArray{
				bastion.PrivateIp,
			},
			ZoneId: pulumi.String(env.DNSZoneID),
			Ttl:    pulumi.Int(300),
		}, pulumi.Parent(bastion))
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
			}, pulumi.Parent(bastion))
			if err != nil {
				return fmt.Errorf("creating bastion route [%s]: %w", routeName, err)
			}
		}

		// Elastic subnet group
		elcSubnetGroup, err := elasticache.NewSubnetGroup(ctx, "elc-subnet-group-"+env.Name, &elasticache.SubnetGroupArgs{
			Name:        pulumi.String(env.Name),
			Description: pulumi.String(env.Name),
			SubnetIds: pulumi.StringArray{
				subnetGroups[_subnetGroupElasticCache][0].ID(),
				subnetGroups[_subnetGroupElasticCache][1].ID(),
				subnetGroups[_subnetGroupElasticCache][2].ID(),
			},
		})
		if err != nil {
			return fmt.Errorf("creating elastic subnet group: %w", err)
		}

		// Elastic cache cluster
		elc, err := elasticache.NewCluster(ctx, "elc-cluster-"+env.Name, &elasticache.ClusterArgs{
			ClusterId:         pulumi.String(env.Name),
			NodeType:          pulumi.String("cache.t2.micro"),
			SubnetGroupName:   elcSubnetGroup.Name,
			Engine:            pulumi.String("redis"),
			EngineVersion:     pulumi.String("5.0.6"),
			NumCacheNodes:     pulumi.Int(1),
			Port:              pulumi.Int(6379),
			MaintenanceWindow: pulumi.String("sat:23:00-sun:01:30"),
			SecurityGroupIds: pulumi.StringArray{
				sg.ID(),
			},
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating elastic cluster: %w", err)
		}

		// API GW
		apigw, err := apigateway.NewRestApi(ctx, "api-gw-"+env.Name, &apigateway.RestApiArgs{
			Name: pulumi.String(env.Name),
			EndpointConfiguration: apigateway.RestApiEndpointConfigurationArgs{
				Types: pulumi.String("REGIONAL"),
			},
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating rest api gw: %w", err)
		}

		resEvents, err := apigateway.NewResource(ctx, "api-gw-res-events-"+env.Name, &apigateway.ResourceArgs{
			RestApi:  apigw.ID(),
			ParentId: apigw.RootResourceId,
			PathPart: pulumi.String("events"),
		}, pulumi.Parent(apigw))
		if err != nil {
			return fmt.Errorf("creating rest api gw resource events: %w", err)
		}

		methodEvents, err := apigateway.NewMethod(ctx, "api-gw-method-events-"+env.Name, &apigateway.MethodArgs{
			RestApi:        apigw.ID(),
			ResourceId:     resEvents.ID(),
			ApiKeyRequired: pulumi.Bool(true),
			HttpMethod:     pulumi.String("POST"),
			Authorization:  pulumi.String("NONE"),
			RequestParameters: pulumi.BoolMap{
				"method.request.header.x-api-key": pulumi.Bool(true),
			},
		}, pulumi.Parent(resEvents))
		if err != nil {
			return fmt.Errorf("creating rest api gw method events: %w", err)
		}

		resLogin, err := apigateway.NewResource(ctx, "api-gw-res-login-"+env.Name, &apigateway.ResourceArgs{
			RestApi:  apigw.ID(),
			ParentId: apigw.RootResourceId,
			PathPart: pulumi.String("login"),
		}, pulumi.Parent(apigw))
		if err != nil {
			return fmt.Errorf("creating rest api gw resource login: %w", err)
		}

		methodLogin, err := apigateway.NewMethod(ctx, "api-gw-method-login-"+env.Name, &apigateway.MethodArgs{
			RestApi:        apigw.ID(),
			ResourceId:     resLogin.ID(),
			ApiKeyRequired: pulumi.Bool(false),
			HttpMethod:     pulumi.String("POST"),
			Authorization:  pulumi.String("NONE"),
		}, pulumi.Parent(resLogin))
		if err != nil {
			return fmt.Errorf("creating rest api gw method login: %w", err)
		}

		domainAPIGw, err := apigateway.NewDomainName(ctx, "api-gw-domain-"+env.Name, &apigateway.DomainNameArgs{
			DomainName: pulumi.Sprintf("bus.%s.%s", env.Name, env.Domain),
			EndpointConfiguration: apigateway.DomainNameEndpointConfigurationArgs{
				Types: pulumi.String("REGIONAL"),
			},
			RegionalCertificateArn: certValidationWildcard.CertificateArn,
			Tags:                   tags,
		}, pulumi.Parent(apigw))
		if err != nil {
			return fmt.Errorf("creating rest api gw domain: %w", err)
		}

		_, err = route53.NewRecord(ctx, "record-api-gw-"+env.Name, &route53.RecordArgs{
			Name: domainAPIGw.DomainName,
			Type: route53.RecordTypeCNAME,
			Records: pulumi.StringArray{
				domainAPIGw.RegionalDomainName,
			},
			ZoneId: pulumi.String(env.DNSZoneID),
			Ttl:    pulumi.Int(300),
		}, pulumi.Parent(domainAPIGw))
		if err != nil {
			return fmt.Errorf("creating record for cert validation for wildcard: %w", err)
		}

		_, err = apigateway.NewBasePathMapping(ctx, "api-gw-path-"+env.Name, &apigateway.BasePathMappingArgs{
			DomainName: domainAPIGw.DomainName,
			RestApi:    apigw.ID(),
		}, pulumi.Parent(domainAPIGw))
		if err != nil {
			return fmt.Errorf("creating rest api gw base path mapping: %w", err)
		}

		// ECS Cluster
		cluster, err := ecs.NewCluster(ctx, "ecs-cluster-"+env.Name, &ecs.ClusterArgs{
			Name: pulumi.String(env.Name),
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating ecs cluster: %w", err)
		}

		roleExecution, err := iam.NewRole(ctx, "role-ecs-cluster-"+env.Name, &iam.RoleArgs{
			Name:             pulumi.Sprintf("%s_ecsTaskExecutionRole", env.Name),
			Description:      pulumi.String(env.Name),
			Path:             pulumi.String("/service-role/"),
			AssumeRolePolicy: pulumi.String(`{"Version":"2008-10-17","Statement":[{"Sid":"","Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			ManagedPolicyArns: pulumi.StringArray{
				pulumi.String("arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"),
			},
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating role task exec ecs cluster: %w", err)
		}

		bucketArtifacts, err := s3.NewBucket(ctx, "bucket-codepipeline-"+env.Name, &s3.BucketArgs{
			Bucket:       pulumi.Sprintf("%s-ci-cd-artifacts", env.Name),
			ForceDestroy: pulumi.Bool(true),
			Tags:         tags,
		})
		if err != nil {
			return fmt.Errorf("creating bucket codepipeline: %w", err)
		}

		roleCodepipeline, err := iam.NewRole(ctx, "role-codepipeline-"+env.Name, &iam.RoleArgs{
			Name:             pulumi.Sprintf("%s_rsb-codepipeline-role", env.Name),
			Description:      pulumi.String(env.Name),
			Path:             pulumi.String("/service-role/"),
			AssumeRolePolicy: pulumi.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			ManagedPolicyArns: pulumi.StringArray{
				pulumi.String("arn:aws:iam::aws:policy/AdministratorAccess"),
			},
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating role codepipeline: %w", err)
		}

		roleBuildpipeline, err := iam.NewRole(ctx, "role-buildpipeline-"+env.Name, &iam.RoleArgs{
			Name:             pulumi.Sprintf("%s_rsb-buildpipeline-role", env.Name),
			Description:      pulumi.String(env.Name),
			Path:             pulumi.String("/service-role/"),
			AssumeRolePolicy: pulumi.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			ManagedPolicyArns: pulumi.StringArray{
				pulumi.String("arn:aws:iam::aws:policy/AdministratorAccess"),
			},
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating role buildpipeline: %w", err)
		}

		// Main load balancer
		lbMain, err := elasticloadbalancingv2.NewLoadBalancer(ctx, "elb-main-"+env.Name, &elasticloadbalancingv2.LoadBalancerArgs{
			Name:     pulumi.Sprintf("%s-services", env.Name),
			Internal: pulumi.Bool(true),
			SecurityGroups: pulumi.StringArray{
				sg.ID(),
			},
			Subnets: pulumi.StringArray{
				subnetGroups[_subnetGroupPrivate][0].ID(),
				subnetGroups[_subnetGroupPrivate][1].ID(),
				subnetGroups[_subnetGroupPrivate][2].ID(),
			},
			Tags: tags,
		})
		if err != nil {
			return fmt.Errorf("creating main load balancer: %w", err)
		}

		tgDefault, err := elasticloadbalancingv2.NewTargetGroup(ctx, "elb-target-group-default-"+env.Name, &elasticloadbalancingv2.TargetGroupArgs{
			Name:       pulumi.Sprintf("%s-default", env.Name),
			TargetType: pulumi.String("ip"),
			Protocol:   pulumi.String("HTTP"),
			Port:       pulumi.Int(80),
			VpcId:      vpc.ID(),
			Tags:       tags,
		})
		if err != nil {
			return fmt.Errorf("creating elb default target group: %w", err)
		}

		listenerHTTP, err := elasticloadbalancingv2.NewListener(ctx, "elb-listener-http-"+env.Name, &elasticloadbalancingv2.ListenerArgs{
			LoadBalancerArn: lbMain.Arn,
			Protocol:        pulumi.String("HTTP"),
			Port:            pulumi.Int(80),
			DefaultActions: elasticloadbalancingv2.ListenerDefaultActionArray{
				elasticloadbalancingv2.ListenerDefaultActionArgs{
					Type:           pulumi.String("forward"),
					TargetGroupArn: tgDefault.Arn,
				},
			},
		}, pulumi.Parent(lbMain))
		if err != nil {
			return fmt.Errorf("creating elb http listener: %w", err)
		}

		listenerHTTPS, err := elasticloadbalancingv2.NewListener(ctx, "elb-listener-https-"+env.Name, &elasticloadbalancingv2.ListenerArgs{
			LoadBalancerArn: lbMain.Arn,
			Protocol:        pulumi.String("HTTPS"),
			Port:            pulumi.Int(443),
			CertificateArn:  certValidationWildcard.CertificateArn,
			DefaultActions: elasticloadbalancingv2.ListenerDefaultActionArray{
				elasticloadbalancingv2.ListenerDefaultActionArgs{
					Type:           pulumi.String("forward"),
					TargetGroupArn: tgDefault.Arn,
				},
			},
		}, pulumi.Parent(lbMain))
		if err != nil {
			return fmt.Errorf("creating elb https listener: %w", err)
		}

		vpcLinks := make(map[string]*apigateway.VpcLink)
		for _, rsbService := range env.RsbServices {
			repo, err := ecr.NewRepository(ctx, fmt.Sprintf("repo-%s-%s", rsbService, env.Name), &ecr.RepositoryArgs{
				Name: pulumi.Sprintf("%s/%s", env.Name, rsbService),
				Tags: tags,
			})
			if err != nil {
				return fmt.Errorf("creating repo [%s]: %w", rsbService, err)
			}

			branch, err := github.NewBranch(ctx, fmt.Sprintf("branch-%s-%s", rsbService, env.Name), &github.BranchArgs{
				SourceBranch: pulumi.String(env.SourceBranch),
				Branch:       pulumi.String(env.Name),
				Repository:   pulumi.Sprintf("%s", rsbService),
			})
			if err != nil {
				return fmt.Errorf("creating branch [%s]: %w", rsbService, err)
			}

			tg, err := elasticloadbalancingv2.NewTargetGroup(ctx, fmt.Sprintf("tg-%s-%s", rsbService, env.Name), &elasticloadbalancingv2.TargetGroupArgs{
				Name:       pulumi.Sprintf(shortEnvName(env.Name, rsbService)),
				TargetType: pulumi.String("ip"),
				Protocol:   pulumi.String("HTTP"),
				Port:       pulumi.Int(80),
				VpcId:      vpc.ID(),
				Tags:       tags,
			})
			if err != nil {
				return fmt.Errorf("creating elb target group [%s]: %w", rsbService, err)
			}

			serviceLoadBalancers := ecs.ServiceLoadBalancerArray{
				ecs.ServiceLoadBalancerArgs{
					TargetGroupArn: tg.Arn,
					ContainerName:  pulumi.String(rsbService),
					ContainerPort:  pulumi.Int(80),
				},
			}

			randomOrder, err := random.NewRandomInteger(ctx, fmt.Sprintf("random-order-%s-%s", rsbService, env.Name), &random.RandomIntegerArgs{
				Min: pulumi.Int(1),
				Max: pulumi.Int(999),
			})
			if err != nil {
				return fmt.Errorf("creating random order integer [%s]: %w", rsbService, err)
			}

			randomPriority, err := random.NewRandomInteger(ctx, fmt.Sprintf("random-priority-%s-%s", rsbService, env.Name), &random.RandomIntegerArgs{
				Min: pulumi.Int(1),
				Max: pulumi.Int(4095),
			})
			if err != nil {
				return fmt.Errorf("creating random priority integer [%s]: %w", rsbService, err)
			}

			_, err = elasticloadbalancingv2.NewListenerRule(ctx, fmt.Sprintf("rule-http-%s-%s", rsbService, env.Name), &elasticloadbalancingv2.ListenerRuleArgs{
				ListenerArn: listenerHTTP.Arn,
				Actions: elasticloadbalancingv2.ListenerRuleActionArray{
					elasticloadbalancingv2.ListenerRuleActionArgs{
						Type:           pulumi.String("forward"),
						TargetGroupArn: tg.Arn,
						Order:          randomOrder.Result,
					},
				},
				Conditions: elasticloadbalancingv2.ListenerRuleConditionArray{
					elasticloadbalancingv2.ListenerRuleConditionArgs{
						HostHeader: elasticloadbalancingv2.ListenerRuleConditionHostHeaderArgs{
							Values: pulumi.StringArray{
								pulumi.Sprintf("%s.services.%s.%s", shortName(rsbService), env.Name, env.Domain),
							},
						},
					},
				},
				Priority: randomPriority.Result,
			}, pulumi.Parent(listenerHTTP))
			if err != nil {
				return fmt.Errorf("creating elb http listener rule [%s]: %w", rsbService, err)
			}

			_, err = elasticloadbalancingv2.NewListenerRule(ctx, fmt.Sprintf("rule-https-%s-%s", rsbService, env.Name), &elasticloadbalancingv2.ListenerRuleArgs{
				ListenerArn: listenerHTTPS.Arn,
				Actions: elasticloadbalancingv2.ListenerRuleActionArray{
					elasticloadbalancingv2.ListenerRuleActionArgs{
						Type:           pulumi.String("forward"),
						TargetGroupArn: tg.Arn,
						Order:          randomOrder.Result,
					},
				},
				Conditions: elasticloadbalancingv2.ListenerRuleConditionArray{
					elasticloadbalancingv2.ListenerRuleConditionArgs{
						HostHeader: elasticloadbalancingv2.ListenerRuleConditionHostHeaderArgs{
							Values: pulumi.StringArray{
								pulumi.Sprintf("%s.services.%s.%s", shortName(rsbService), env.Name, env.Domain),
							},
						},
					},
				},
				Priority: randomPriority.Result,
			}, pulumi.Parent(listenerHTTPS))
			if err != nil {
				return fmt.Errorf("creating elb https listener rule [%s]: %w", rsbService, err)
			}

			_, err = route53.NewRecord(ctx, fmt.Sprintf("record-https-%s-%s", rsbService, env.Name), &route53.RecordArgs{
				Name: pulumi.Sprintf("%s.services.%s.%s.", shortName(rsbService), env.Name, env.Domain),
				Type: route53.RecordTypeCNAME,
				Records: pulumi.StringArray{
					lbMain.DnsName,
				},
				ZoneId: pulumi.String(env.DNSZoneID),
				Ttl:    pulumi.Int(300),
			})
			if err != nil {
				return fmt.Errorf("creating record [%s]: %w", rsbService, err)
			}

			if _apiGWServices[rsbService] {
				nlb, err := elasticloadbalancingv2.NewLoadBalancer(ctx, fmt.Sprintf("lb-network-%s-%s", rsbService, env.Name), &elasticloadbalancingv2.LoadBalancerArgs{
					Name:             pulumi.String(shortEnvName(env.Name, rsbService)),
					LoadBalancerType: pulumi.String("network"),
					Internal:         pulumi.Bool(true),
					Subnets: pulumi.StringArray{
						subnetGroups[_subnetGroupPublic][0].ID(),
						subnetGroups[_subnetGroupPublic][1].ID(),
						subnetGroups[_subnetGroupPublic][2].ID(),
					},
					Tags: tags,
				})
				if err != nil {
					return fmt.Errorf("creating network load balancer [%s]: %w", rsbService, err)
				}

				tgNLB, err := elasticloadbalancingv2.NewTargetGroup(ctx, fmt.Sprintf("nlb-tcp-%s-%s", rsbService, env.Name), &elasticloadbalancingv2.TargetGroupArgs{
					Name:       pulumi.Sprintf("%s-nlb", shortEnvName(env.Name, rsbService)),
					TargetType: pulumi.String("ip"),
					Protocol:   pulumi.String("TCP"),
					Port:       pulumi.Int(80),
					VpcId:      vpc.ID(),
					Tags:       tags,
				})
				if err != nil {
					return fmt.Errorf("creating nlb target group [%s]: %w", rsbService, err)
				}

				serviceLoadBalancers = append(serviceLoadBalancers, ecs.ServiceLoadBalancerArgs{
					TargetGroupArn: tgNLB.Arn,
					ContainerName:  pulumi.String(rsbService),
					ContainerPort:  pulumi.Int(80),
				})

				_, err = elasticloadbalancingv2.NewListener(ctx, fmt.Sprintf("nlb-listener-http-%s-%s", rsbService, env.Name), &elasticloadbalancingv2.ListenerArgs{
					LoadBalancerArn: nlb.Arn,
					Protocol:        pulumi.String("TCP"),
					Port:            pulumi.Int(80),
					DefaultActions: elasticloadbalancingv2.ListenerDefaultActionArray{
						elasticloadbalancingv2.ListenerDefaultActionArgs{
							Type:           pulumi.String("forward"),
							TargetGroupArn: tgNLB.Arn,
						},
					},
				}, pulumi.Parent(nlb))
				if err != nil {
					return fmt.Errorf("creating nlb http listener [%s]: %w", rsbService, err)
				}

				_, err = elasticloadbalancingv2.NewListener(ctx, fmt.Sprintf("nlb-listener-https-%s-%s", rsbService, env.Name), &elasticloadbalancingv2.ListenerArgs{
					LoadBalancerArn: nlb.Arn,
					Protocol:        pulumi.String("TLS"),
					Port:            pulumi.Int(443),
					CertificateArn:  certValidationWildcard.CertificateArn,
					DefaultActions: elasticloadbalancingv2.ListenerDefaultActionArray{
						elasticloadbalancingv2.ListenerDefaultActionArgs{
							Type:           pulumi.String("forward"),
							TargetGroupArn: tgNLB.Arn,
						},
					},
				}, pulumi.Parent(nlb))
				if err != nil {
					return fmt.Errorf("creating nlb https listener [%s]: %w", rsbService, err)
				}

				vpcLink, err := apigateway.NewVpcLink(ctx, fmt.Sprintf("vpc-link-%s-%s", rsbService, env.Name), &apigateway.VpcLinkArgs{
					Name:      pulumi.Sprintf("%s-%s", env.Name, rsbService),
					TargetArn: nlb.Arn,
					Tags:      tags,
				})
				if err != nil {
					return fmt.Errorf("creating vpc link [%s]: %w", rsbService, err)
				}

				vpcLinks[rsbService] = vpcLink
			}

			containerDefinitions := pulumi.All(
				branch.Branch,
				repo.RepositoryUrl,
				elc.CacheNodes.Index(pulumi.Int(0)).Address(),
				apigw.ID().ToStringOutput(),
				rsbService,
				dbMasterUserPassword,
				rmqMasterUserPassword,
			).ApplyT(func(args []interface{}) (string, error) {
				rsbService := args[4].(string)

				baseTaskDef, err := fetchFileFromGithubRepo(cred.GithubOrgName, rsbService, env.Name, "BaseTaskDefinition.json", cred.GithubAuthToken)
				if err != nil {
					return "", fmt.Errorf("fetch base task def [%s]: %w", rsbService, err)
				}

				var containerDefinitions = struct {
					Definitions []map[string]interface{} `json:"containerDefinitions"`
				}{}

				err = json.Unmarshal([]byte(baseTaskDef), &containerDefinitions)
				if err != nil {
					return "", fmt.Errorf("unmarshal base task def [%s]: %w", rsbService, err)
				}

				containerDefinitions.Definitions[0]["name"] = rsbService
				containerDefinitions.Definitions[0]["portMappings"] = []map[string]interface{}{
					{
						"containerPort": 80,
						"hostPort":      80,
						"protocol":      "tcp",
					},
				}
				containerDefinitions.Definitions[0]["ulimits"] = []map[string]interface{}{
					{
						"name":      "nofile",
						"softLimit": 1024000,
						"hardLimit": 1024000,
					},
				}
				containerDefinitions.Definitions[0]["image"] = fmt.Sprintf("%s:%s", args[1], env.Name)

				svcShortName := shortName(rsbService)
				elcHostname := args[2].(*string)
				apigwID := args[3].(string)
				dbMasterUserPassword := args[5].(string)
				rmqMasterUserPassword := args[6].(string)

				mappings := map[string]string{
					"REPLACEME_RSBServicesCORSOriginURLs":       fmt.Sprintf("%s,https://admin-ui.services.%s.%s", env.ServicesCORSOriginURLs, env.Name, env.Domain),
					"REPLACEME_BASTION_HOST":                    fmt.Sprintf("srv.%s.%s", env.Name, env.Domain),
					"REPLACEME_AWS_API_GW_ID":                   apigwID,
					"REPLACEME_RSB_API_BASE_URL":                fmt.Sprintf("https://%s.execute-api.eu-west-1.amazonaws.com/v1", apigwID),
					"REPLACEME_SERVICE_REGISTRY_BASE_URL":       fmt.Sprintf("https://servicerepository.services.%s.%s", env.Name, env.Domain),
					"REPLACEME_VENTURE_CONFIG_SERVICE_BASE_URL": fmt.Sprintf("https://ventureconfig.services.%s.%s", env.Name, env.Domain),
					"REPLACEME_FEEDER_URL":                      fmt.Sprintf("https://feeder.services.%s.%s", env.Name, env.Domain),
					"REPLACEME_USER_SERVICE_BASE_URL":           fmt.Sprintf("https://users.services.%s.%s", env.Name, env.Domain),
					// "REPLACEME_E2EMON_BASE_URL":                  e2eMonBaseUrl(),
					// "REPLACEME_DB_HOST":                          env.DBHostname,
					// "REPLACEME_DBHostname":                       env.DBHostname,
					"REPLACEME_RMQMasterUsername":     "admin",
					"REPLACEME_RMQMasterUserPassword": rmqMasterUserPassword,
					// "REPLACEME_RMQVHost":                         env.RMQVHost,
					"REPLACEME_RMQServer": fmt.Sprintf("srv.%s.%s", env.Name, env.Domain),
					// "REPLACEME_DBMasterUsername":                 env.DBMasterUsername,
					"REPLACEME_DBMasterUserPassword": dbMasterUserPassword,
					"REPLACEME_AwsAccessKeyID":       cred.AWSAccessKeyID,
					"REPLACEME_AwsRegion":            cred.AWSRegion,
					"REPLACEME_AwsSecretAccessKey":   cred.AWSSecretAccessKey,
					"REPLACEME_GithubOrgname":        cred.GithubOrgName,
					"REPLACEME_GithubOauthToken":     cred.GithubAuthToken,
					"REPLACEME_DNSZoneID":            env.DNSZoneID,
					"REPLACEME_Domain":               env.Domain,
					"REPLACEME_LibDBTable":           fmt.Sprintf("%s_%s", env.Name, svcShortName),
					"REPLACEME_DB_DATABASE":          fmt.Sprintf("%s_%s", env.Name, svcShortName),
					"REPLACEME_SLACK_WEBHOOK":        env.SlackWebHook,
					"REPLACEME_ElasticacheHostname":  *elcHostname,
					// "REPLACEME_ELASTICSEARCH_URL":                fmt.Sprintf("https://%s", env.ElasticSearchEndpoint),
					"REPLACEME_SERVICE_REGISTRY_CACHE_TAG":       fmt.Sprintf("rsb_sr_%s", env.Name),
					"REPLACEME_VENTURE_CONFIG_SERVICE_CACHE_TAG": fmt.Sprintf("rsb_vc_%s", env.Name),
					"REPLACEME_BACKUP_INTERVAL":                  "5",
					"REPLACEME_RSB_ENV":                          env.Name,
					// "REPLACEME_DATADOG_API_BASE_URL":             env.DDApiBaseURL,
					// "REPLACEME_DATADOG_API_KEY":                  env.DDApiKey,
					// "REPLACEME_DATADOG_APP_KEY":                  env.DDAppKey,
					"REPLACEME_RELEASE_NAME":          env.Name,
					"REPLACEME_MESSAGE_BROKER_DRIVER": env.BrokerDriver,
					"REPLACEME_MqAMQPPort":            "5672",
					"REPLACEME_MqRabbitAdminPort":     "15672",
					"REPLACEME_RMQAdminURL":           fmt.Sprintf("http://srv.%s.%s:15672", env.Name, env.Domain),
					"REPLACEME_MqProtocol":            "amqp",
				}

				environments, ok := containerDefinitions.Definitions[0]["environment"].([]interface{})
				if !ok {
					return "", fmt.Errorf("unexpected environments type [%s]", rsbService)
				}

				for i, raw := range environments {
					environment := raw.(map[string]interface{})
					if val, found := mappings[environment["value"].(string)]; found {
						environment["value"] = val
					}
					environments[i] = environment
				}

				containerDefinitions.Definitions[0]["environment"] = environments

				jsonB, err := json.Marshal(containerDefinitions.Definitions)
				if err != nil {
					return "", fmt.Errorf("marshal base task def [%s]: %w", rsbService, err)
				}

				return string(jsonB), nil
			}).(pulumi.StringOutput)

			taskDef, err := ecs.NewTaskDefinition(ctx, fmt.Sprintf("task-def-%s-%s", rsbService, env.Name), &ecs.TaskDefinitionArgs{
				ContainerDefinitions: containerDefinitions,
				Family:               pulumi.Sprintf("%s-%s", env.Name, rsbService),
				ExecutionRoleArn:     roleExecution.Arn,
				NetworkMode:          pulumi.String("awsvpc"),
				Cpu:                  pulumi.String(strconv.Itoa(env.EcsCPU)),
				Memory:               pulumi.String(strconv.Itoa(env.EcsMemory)),
				RequiresCompatibilities: pulumi.StringArray{
					pulumi.String("FARGATE"),
				},
				Tags: tags,
			})
			if err != nil {
				return fmt.Errorf("creating task definition [%s]: %w", rsbService, err)
			}

			_, err = codebuild.NewProject(ctx, fmt.Sprintf("cb-project-%s-%s", rsbService, env.Name), &codebuild.ProjectArgs{
				Artifacts: codebuild.ProjectArtifactsArgs{
					Type: pulumi.String("NO_ARTIFACTS"),
				},
				Description: pulumi.Sprintf("Build project for %s in %s", rsbService, env.Name),
				Environment: codebuild.ProjectEnvironmentArgs{
					ComputeType:              pulumi.String("BUILD_GENERAL1_SMALL"),
					Image:                    pulumi.String("aws/codebuild/standard:1.0"),
					ImagePullCredentialsType: pulumi.String("CODEBUILD"),
					PrivilegedMode:           pulumi.Bool(true),
					Type:                     pulumi.String("LINUX_CONTAINER"),
					EnvironmentVariables: codebuild.ProjectEnvironmentEnvironmentVariableArray{
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_TAG"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(env.Name),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_REPOSITORY_URI"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: repo.RepositoryUrl,
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_SLACK_WEBHOOK"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(env.SlackWebHook),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_DOMAIN"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(env.Domain),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_BASTION_HOST"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.Sprintf("srv.%s.%s", env.Name, env.Domain),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_ENV_BASTION_URL"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.Sprintf("http://bastion.%s.%s", env.Name, env.Domain),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("GITHUBOAUTHTOKEN"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(cred.GithubAuthToken),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("DOCKER_USER"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(cred.DockerHubUsername),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("DOCKER_PASSWORD"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(cred.DockerHubPassword),
						},
					},
				},
				Name:        pulumi.Sprintf("%s_%s", env.Name, rsbService),
				ServiceRole: roleBuildpipeline.Arn,
				Source: &codebuild.ProjectSourceArgs{
					GitCloneDepth: pulumi.Int(1),
					Location:      pulumi.Sprintf("https://github.com/%s/%s.git", cred.GithubOrgName, rsbService),
					Type:          pulumi.String("GITHUB"),
				},
				SourceVersion: pulumi.String(env.Name),
				Tags:          tags,
			})
			if err != nil {
				return fmt.Errorf("creating codebuild project [%s]: %w", rsbService, err)
			}

			_, err = codepipeline.NewPipeline(ctx, fmt.Sprintf("code-pipeline-%s-%s", rsbService, env.Name), &codepipeline.PipelineArgs{
				ArtifactStore: codepipeline.PipelineArtifactStoreArgs{
					Location: bucketArtifacts.Bucket,
					Type:     pulumi.String("S3"),
				},
				Name:    pulumi.Sprintf("%s@%s", rsbService, env.Name),
				RoleArn: roleCodepipeline.Arn,
				Stages: codepipeline.PipelineStageArray{
					// Stage 1: Checkout sourcecode
					codepipeline.PipelineStageArgs{
						Name: pulumi.String("SourceStage"),
						Actions: codepipeline.PipelineStageActionArray{
							codepipeline.PipelineStageActionArgs{
								Region:   pulumi.String(cred.AWSRegion),
								Category: pulumi.String("Source"),
								Owner:    pulumi.String("ThirdParty"),
								Provider: pulumi.String("GitHub"),
								Version:  pulumi.String("1"),
								OutputArtifacts: pulumi.StringArray{
									pulumi.String("source"),
								},
								Configuration: pulumi.StringMap{
									"Owner":                pulumi.String(cred.GithubOrgName),
									"Repo":                 pulumi.String(rsbService),
									"PollForSourceChanges": pulumi.String("true"),
									"Branch":               pulumi.String(env.Name),
									"OAuthToken":           pulumi.String(cred.GithubAuthToken),
								},
								Name:     pulumi.String("Source"),
								RunOrder: pulumi.Int(1),
							},
						},
					},
					// Stage 2: Build & push docker image
					codepipeline.PipelineStageArgs{
						Name: pulumi.String("BuildStage"),
						Actions: codepipeline.PipelineStageActionArray{
							codepipeline.PipelineStageActionArgs{
								Region:   pulumi.String(cred.AWSRegion),
								Category: pulumi.String("Build"),
								Owner:    pulumi.String("AWS"),
								Provider: pulumi.String("CodeBuild"),
								Version:  pulumi.String("1"),
								Configuration: pulumi.StringMap{
									"ProjectName": pulumi.Sprintf("%s_%s", env.Name, rsbService),
								},
								InputArtifacts: pulumi.StringArray{
									pulumi.String("source"),
								},
								OutputArtifacts: pulumi.StringArray{
									pulumi.String("imagedefinitions"),
								},
								Name:     pulumi.String("BuildAction"),
								RunOrder: pulumi.Int(333),
							},
						},
					},
					// Stage 3: Deploy to ECS cluster / update service
					codepipeline.PipelineStageArgs{
						Name: pulumi.String("DeployStage"),
						Actions: codepipeline.PipelineStageActionArray{
							codepipeline.PipelineStageActionArgs{
								Region:   pulumi.String(cred.AWSRegion),
								Category: pulumi.String("Deploy"),
								Owner:    pulumi.String("AWS"),
								Provider: pulumi.String("ECS"),
								Version:  pulumi.String("1"),
								Configuration: pulumi.StringMap{
									"ClusterName": pulumi.String(env.Name),
									"ServiceName": pulumi.String(rsbService),
								},
								InputArtifacts: pulumi.StringArray{
									pulumi.String("imagedefinitions"),
								},
								Name:     pulumi.String("DeployAction"),
								RunOrder: pulumi.Int(666),
							},
						},
					},
				},
				Tags: tags,
			})
			if err != nil {
				return fmt.Errorf("creating code pipeline [%s]: %w", rsbService, err)
			}

			_, err = ecs.NewService(ctx, fmt.Sprintf("ecs-service-%s-%s", rsbService, env.Name), &ecs.ServiceArgs{
				Cluster:        cluster.ID(),
				Name:           pulumi.String(rsbService),
				LaunchType:     pulumi.String("FARGATE"),
				TaskDefinition: taskDef.Arn,
				DesiredCount:   pulumi.Int(1),
				LoadBalancers:  serviceLoadBalancers,
				NetworkConfiguration: ecs.ServiceNetworkConfigurationArgs{
					Subnets: pulumi.StringArray{
						subnetGroups[_subnetGroupDatabase][0].ID(),
						subnetGroups[_subnetGroupDatabase][1].ID(),
						subnetGroups[_subnetGroupDatabase][2].ID(),
					},
					SecurityGroups: pulumi.StringArray{
						sg.ID(),
					},
					AssignPublicIp: pulumi.Bool(false),
				},
				Tags: tags,
			})
			if err != nil {
				return fmt.Errorf("creating ecs service [%s]: %w", rsbService, err)
			}
		}

		integEvents, err := apigateway.NewIntegration(ctx, "api-gw-integ-events-"+env.Name, &apigateway.IntegrationArgs{
			RestApi:               apigw.ID(),
			ResourceId:            resEvents.ID(),
			HttpMethod:            methodEvents.HttpMethod,
			IntegrationHttpMethod: methodEvents.HttpMethod,
			Type:                  pulumi.String("HTTP"),
			PassthroughBehavior:   pulumi.String("WHEN_NO_MATCH"),
			ConnectionType:        pulumi.String("VPC_LINK"),
			ConnectionId:          vpcLinks["rsb-service-feeder"].ID(),
			RequestParameters: pulumi.StringMap{
				"integration.request.header.x-api-key": pulumi.String("method.request.header.x-api-key"),
			},
			Uri: pulumi.Sprintf("https://feeder.services.%s.%s/api/events", env.Name, env.Domain),
		})
		if err != nil {
			return fmt.Errorf("creating rest api gw integration events: %w", err)
		}

		integLogin, err := apigateway.NewIntegration(ctx, "api-gw-integ-login-"+env.Name, &apigateway.IntegrationArgs{
			RestApi:               apigw.ID(),
			ResourceId:            resLogin.ID(),
			HttpMethod:            methodLogin.HttpMethod,
			IntegrationHttpMethod: methodLogin.HttpMethod,
			Type:                  pulumi.String("HTTP"),
			PassthroughBehavior:   pulumi.String("WHEN_NO_MATCH"),
			ConnectionType:        pulumi.String("VPC_LINK"),
			ConnectionId:          vpcLinks["rsb-service-users"].ID(),
			Uri:                   pulumi.Sprintf("https://users.services.%s.%s/api/login", env.Name, env.Domain),
		})
		if err != nil {
			return fmt.Errorf("creating rest api gw integration login: %w", err)
		}

		_, err = apigateway.NewDeployment(ctx, "api-gw-deployment-"+env.Name, &apigateway.DeploymentArgs{
			RestApi:          apigw.ID(),
			StageName:        pulumi.String("v1"),
			StageDescription: pulumi.String("v1"),
			Description:      pulumi.String("Init"),
		}, pulumi.DependsOn([]pulumi.Resource{integEvents, integLogin}))
		if err != nil {
			return fmt.Errorf("creating rest api gw stage: %w", err)
		}

		ctx.Export("vpc", vpc.Arn)
		return nil
	}
}
