package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/acm"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/apigateway"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/codebuild"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/codepipeline"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ecr"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ecs"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/elasticache"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/elasticloadbalancingv2"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/elasticsearch"
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
		githubProvider, err := github.NewProvider(ctx, "provider-github-"+env.Name, &github.ProviderArgs{
			Owner: pulumi.String(cred.GithubOrgName),
			Token: pulumi.String(cred.GithubAuthToken),
		})
		if err != nil {
			return fmt.Errorf("creating github provider: %w", err)
		}

		awsProvider, err := aws.NewProvider(ctx, "provider-aws-"+env.Name, &aws.ProviderArgs{
			AccessKey: pulumi.String(cred.AWSAccessKeyID),
			SecretKey: pulumi.String(cred.AWSSecretAccessKey),
			Region:    pulumi.String(cred.AWSRegion),
			DefaultTags: aws.ProviderDefaultTagsArgs{
				Tags: pulumi.StringMap{
					"RSB_ENV": pulumi.String(env.Name),
					"Name":    pulumi.String(env.Name),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("creating aws provider: %w", err)
		}

		// Resource Group
		_, err = resourcegroups.NewGroup(ctx, "rg-"+env.Name, &resourcegroups.GroupArgs{
			Name:        pulumi.String(env.Name),
			Description: pulumi.String("Everything tagged " + env.Name),
			ResourceQuery: &resourcegroups.GroupResourceQueryArgs{
				Query: pulumi.Sprintf("{\"ResourceTypeFilters\": [\"AWS::AllSupported\"], \"TagFilters\": [{\"Key\": \"RSB_ENV\", \"Values\": [\"%s\"]}]}", env.Name),
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating resource group: %w", err)
		}

		// VPC
		vpc, err := ec2.NewVpc(ctx, "vpc-"+env.Name, &ec2.VpcArgs{
			CidrBlock:                    pulumi.String("10.15.96.0/19"),
			AssignGeneratedIpv6CidrBlock: pulumi.Bool(true),
		}, pulumi.Provider(awsProvider))
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
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating vpc subnet [%s]: %w", name, err)
			}

			subnetGroups[subnet.Group] = append(subnetGroups[subnet.Group], sbnt)
		}

		// Internet Gateway
		igw, err := ec2.NewInternetGateway(ctx, "igw-"+env.Name, &ec2.InternetGatewayArgs{
			VpcId: vpc.ID(),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating internet gateway: %w", err)
		}

		// Elastic IP
		eip, err := ec2.NewEip(ctx, "eip-"+env.Name, &ec2.EipArgs{}, pulumi.DependsOn([]pulumi.Resource{igw}), pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating elastic ip: %w", err)
		}

		// NAT Gateway
		nat, err := ec2.NewNatGateway(ctx, "nat-"+env.Name, &ec2.NatGatewayArgs{
			AllocationId: eip.ID(),
			SubnetId:     subnetGroups[_subnetGroupPublic][0].ID(),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating internet gateway: %w", err)
		}

		// Route tables
		routeTables := make(map[string]*ec2.RouteTable)
		for groupName, subnets := range subnetGroups {
			routeTableName := "rt-" + env.Name + "-" + groupName
			rt, err := ec2.NewRouteTable(ctx, routeTableName, &ec2.RouteTableArgs{
				VpcId: vpc.ID(),
			}, pulumi.Provider(awsProvider))
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
			_, err = ec2.NewRoute(ctx, routeName, routeArgs, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating default route [%s]: %w", routeName, err)
			}

			// Route table assiociations
			for i, subnet := range subnets {
				routeAssocName := fmt.Sprintf("rt-assoc-%s-%s-%d", env.Name, groupName, i)
				_, err = ec2.NewRouteTableAssociation(ctx, routeAssocName, &ec2.RouteTableAssociationArgs{
					RouteTableId: rt.ID(),
					SubnetId:     subnet.ID(),
				}, pulumi.Provider(awsProvider))
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
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating security group: %w", err)
		}

		// Certificate for services
		certServices, err := acm.NewCertificate(ctx, "cert-services-"+env.Name, &acm.CertificateArgs{
			DomainName:       pulumi.Sprintf("*.services.%s.%s", env.Name, env.AwsServices.Route53.Domain),
			ValidationMethod: pulumi.String("DNS"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating cert for services: %w", err)
		}

		// Validation CNAME record for certificate services
		recordCertServices, err := route53.NewRecord(ctx, "record-cert-services-validation-"+env.Name, &route53.RecordArgs{
			Name: certServices.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordName().Elem(),
			Type: certServices.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordType().Elem(),
			Records: pulumi.StringArray{
				certServices.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordValue().Elem(),
			},
			ZoneId: pulumi.String(env.AwsServices.Route53.DNSZoneID),
			Ttl:    pulumi.Int(300),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating record for cert validation for services: %w", err)
		}

		// Request certificate validation for services
		certValidationServicesWildcard, err := acm.NewCertificateValidation(ctx, "cert-services-validation-"+env.Name, &acm.CertificateValidationArgs{
			CertificateArn: certServices.Arn,
			ValidationRecordFqdns: pulumi.StringArray{
				recordCertServices.Fqdn,
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating cert validation for services: %w", err)
		}

		// Certificate for wildcard
		certWildcard, err := acm.NewCertificate(ctx, "cert-wildcard-"+env.Name, &acm.CertificateArgs{
			DomainName:       pulumi.Sprintf("*.%s.%s", env.Name, env.AwsServices.Route53.Domain),
			ValidationMethod: pulumi.String("DNS"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating cert for wildcard: %w", err)
		}

		// Validation CNAME record for certificate wildcard
		recordCertWildcard, err := route53.NewRecord(ctx, "record-cert-wildcard-validation-"+env.Name, &route53.RecordArgs{
			Name: certWildcard.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordName().Elem(),
			Type: certWildcard.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordType().Elem(),
			Records: pulumi.StringArray{
				certWildcard.DomainValidationOptions.Index(pulumi.Int(0)).ResourceRecordValue().Elem(),
			},
			ZoneId: pulumi.String(env.AwsServices.Route53.DNSZoneID),
			Ttl:    pulumi.Int(300),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating record for cert validation for wildcard: %w", err)
		}

		// Request certificate validation for wildcard
		certValidationWildcard, err := acm.NewCertificateValidation(ctx, "cert-wildcard-validation-"+env.Name, &acm.CertificateValidationArgs{
			CertificateArn: certWildcard.Arn,
			ValidationRecordFqdns: pulumi.StringArray{
				recordCertWildcard.Fqdn,
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating cert validation for wildcard: %w", err)
		}

		var dbMasterUserPassword pulumi.StringInput
		if env.AwsServices.RDS.Enabled {
			if env.AwsServices.RDS.Password == "" {
				dbMasterUserPasswordGenerated, err := random.NewRandomPassword(ctx, "password-db-master-user-password-"+env.Name, &random.RandomPasswordArgs{
					Length:  pulumi.Int(32),
					Lower:   pulumi.Bool(true),
					Upper:   pulumi.Bool(true),
					Special: pulumi.Bool(false),
				})
				if err != nil {
					return fmt.Errorf("creating db master user password: %w", err)
				}

				dbMasterUserPassword = dbMasterUserPasswordGenerated.Result
			} else {
				dbMasterUserPassword = pulumi.String(env.AwsServices.RDS.Password)
			}
		} else {
			dbMasterUserPassword = pulumi.String("")
		}

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
			if env.RsbServices.Broker.Password != "" {
				return env.RsbServices.Broker.Password
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
			Ami:             pulumi.String(env.AwsServices.Bastion.AMIID),
			InstanceType:    ec2.InstanceType_T3_Micro,
			SubnetId:        subnetGroups[_subnetGroupPublic][0].ID(),
			SourceDestCheck: pulumi.Bool(false),
			VpcSecurityGroupIds: pulumi.StringArray{
				sg.ID(),
			},
			UserDataBase64: UserDataBase64,
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating ec2 instance for bastion: %w", err)
		}

		// Public A record for bastion instance
		bastionPubRecord, err := route53.NewRecord(ctx, "record-pub-bastion"+env.Name, &route53.RecordArgs{
			Name: pulumi.Sprintf("bastion.%s.%s", env.Name, env.AwsServices.Route53.Domain),
			Type: route53.RecordTypeA,
			Records: pulumi.StringArray{
				bastion.PublicIp,
			},
			ZoneId: pulumi.String(env.AwsServices.Route53.DNSZoneID),
			Ttl:    pulumi.Int(300),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating public A record for bastion: %w", err)
		}

		// Private A record for bastion instance
		bastionPrivRecord, err := route53.NewRecord(ctx, "record-priv-bastion"+env.Name, &route53.RecordArgs{
			Name: pulumi.Sprintf("srv.%s.%s", env.Name, env.AwsServices.Route53.Domain),
			Type: route53.RecordTypeA,
			Records: pulumi.StringArray{
				bastion.PrivateIp,
			},
			ZoneId: pulumi.String(env.AwsServices.Route53.DNSZoneID),
			Ttl:    pulumi.Int(300),
		}, pulumi.Provider(awsProvider))
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
			}, pulumi.Provider(awsProvider))
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
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating elastic subnet group: %w", err)
		}

		// Elastic search
		var esEndpoint pulumi.StringInput
		if env.AwsServices.ES.Enabled {
			// _, err = iam.NewServiceLinkedRole(ctx, "es-iam-slr-"+env.Name, &iam.ServiceLinkedRoleArgs{
			// 	AwsServiceName: pulumi.String("es.amazonaws.com"),
			// })
			// if err != nil {
			// 	return fmt.Errorf("creating elastic search iam service linked role: %w", err)
			// }

			es, err := elasticsearch.NewDomain(ctx, "es-domain-"+env.Name, &elasticsearch.DomainArgs{
				AccessPolicies: pulumi.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"es:*","Resource":"arn:aws:es:*:*:*"}]}`),
				DomainEndpointOptions: elasticsearch.DomainDomainEndpointOptionsArgs{
					EnforceHttps:      pulumi.Bool(true),
					TlsSecurityPolicy: pulumi.String("Policy-Min-TLS-1-2-2019-07"),
				},
				DomainName: pulumi.String(env.Name),
				EbsOptions: elasticsearch.DomainEbsOptionsArgs{
					EbsEnabled: pulumi.Bool(true),
					VolumeSize: pulumi.Int(10),
					VolumeType: pulumi.String("gp2"),
				},
				ClusterConfig: elasticsearch.DomainClusterConfigArgs{
					InstanceCount: pulumi.Int(2),
					InstanceType:  pulumi.String("t2.small.elasticsearch"),
				},
				ElasticsearchVersion: pulumi.String(env.AwsServices.ES.Version),
				VpcOptions: elasticsearch.DomainVpcOptionsArgs{
					SecurityGroupIds: pulumi.StringArray{
						sg.ID(),
					},
					SubnetIds: pulumi.StringArray{
						subnetGroups[_subnetGroupDatabase][0].ID(),
					},
				},
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating elastic search domain: %w", err)
			}

			esEndpoint = es.Endpoint
		} else {
			esEndpoint = pulumi.String("")
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
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating elastic cluster: %w", err)
		}

		// API GW
		apigw, err := apigateway.NewRestApi(ctx, "api-gw-"+env.Name, &apigateway.RestApiArgs{
			Name: pulumi.String(env.Name),
			EndpointConfiguration: apigateway.RestApiEndpointConfigurationArgs{
				Types: pulumi.String("REGIONAL"),
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating rest api gw: %w", err)
		}

		resEvents, err := apigateway.NewResource(ctx, "api-gw-res-events-"+env.Name, &apigateway.ResourceArgs{
			RestApi:  apigw.ID(),
			ParentId: apigw.RootResourceId,
			PathPart: pulumi.String("events"),
		}, pulumi.Provider(awsProvider))
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
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating rest api gw method events: %w", err)
		}

		resLogin, err := apigateway.NewResource(ctx, "api-gw-res-login-"+env.Name, &apigateway.ResourceArgs{
			RestApi:  apigw.ID(),
			ParentId: apigw.RootResourceId,
			PathPart: pulumi.String("login"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating rest api gw resource login: %w", err)
		}

		methodLogin, err := apigateway.NewMethod(ctx, "api-gw-method-login-"+env.Name, &apigateway.MethodArgs{
			RestApi:        apigw.ID(),
			ResourceId:     resLogin.ID(),
			ApiKeyRequired: pulumi.Bool(false),
			HttpMethod:     pulumi.String("POST"),
			Authorization:  pulumi.String("NONE"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating rest api gw method login: %w", err)
		}

		domainAPIGw, err := apigateway.NewDomainName(ctx, "api-gw-domain-"+env.Name, &apigateway.DomainNameArgs{
			DomainName: pulumi.Sprintf("bus.%s.%s", env.Name, env.AwsServices.Route53.Domain),
			EndpointConfiguration: apigateway.DomainNameEndpointConfigurationArgs{
				Types: pulumi.String("REGIONAL"),
			},
			RegionalCertificateArn: certValidationWildcard.CertificateArn,
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating rest api gw domain: %w", err)
		}

		_, err = route53.NewRecord(ctx, "record-api-gw-"+env.Name, &route53.RecordArgs{
			Name: domainAPIGw.DomainName,
			Type: route53.RecordTypeCNAME,
			Records: pulumi.StringArray{
				domainAPIGw.RegionalDomainName,
			},
			ZoneId: pulumi.String(env.AwsServices.Route53.DNSZoneID),
			Ttl:    pulumi.Int(300),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating record for cert validation for wildcard: %w", err)
		}

		_, err = apigateway.NewBasePathMapping(ctx, "api-gw-path-"+env.Name, &apigateway.BasePathMappingArgs{
			DomainName: domainAPIGw.DomainName,
			RestApi:    apigw.ID(),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating rest api gw base path mapping: %w", err)
		}

		// ECS Cluster
		cluster, err := ecs.NewCluster(ctx, "ecs-cluster-"+env.Name, &ecs.ClusterArgs{
			Name: pulumi.String(env.Name),
		}, pulumi.Provider(awsProvider))
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
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating role task exec ecs cluster: %w", err)
		}

		bucketArtifacts, err := s3.NewBucket(ctx, "bucket-codepipeline-"+env.Name, &s3.BucketArgs{
			Bucket:       pulumi.Sprintf("%s-ci-cd-artifacts", env.Name),
			ForceDestroy: pulumi.Bool(true),
		}, pulumi.Provider(awsProvider))
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
		}, pulumi.Provider(awsProvider))
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
		}, pulumi.Provider(awsProvider))
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
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating main load balancer: %w", err)
		}

		tgDefault, err := elasticloadbalancingv2.NewTargetGroup(ctx, "elb-target-group-default-"+env.Name, &elasticloadbalancingv2.TargetGroupArgs{
			Name:       pulumi.Sprintf("%s-default", env.Name),
			TargetType: pulumi.String("ip"),
			Protocol:   pulumi.String("HTTP"),
			Port:       pulumi.Int(80),
			VpcId:      vpc.ID(),
		}, pulumi.Provider(awsProvider))
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
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating elb http listener: %w", err)
		}

		listenerHTTPS, err := elasticloadbalancingv2.NewListener(ctx, "elb-listener-https-"+env.Name, &elasticloadbalancingv2.ListenerArgs{
			LoadBalancerArn: lbMain.Arn,
			Protocol:        pulumi.String("HTTPS"),
			Port:            pulumi.Int(443),
			CertificateArn:  certValidationServicesWildcard.CertificateArn,
			DefaultActions: elasticloadbalancingv2.ListenerDefaultActionArray{
				elasticloadbalancingv2.ListenerDefaultActionArgs{
					Type:           pulumi.String("forward"),
					TargetGroupArn: tgDefault.Arn,
				},
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating elb https listener: %w", err)
		}

		vpcLinkIDs := make(pulumi.StringMap)
		serviceRecords := make(pulumi.StringMap)
		for _, rsbService := range env.RsbServices.Services {
			repo, err := ecr.NewRepository(ctx, fmt.Sprintf("repo-%s-%s", rsbService.Name, env.Name), &ecr.RepositoryArgs{
				Name: pulumi.Sprintf("%s/%s", env.Name, rsbService.Name),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating repo [%s]: %w", rsbService.Name, err)
			}

			branch, err := github.NewBranch(ctx, fmt.Sprintf("branch-%s-%s", rsbService.Name, env.Name), &github.BranchArgs{
				SourceBranch: pulumi.String(rsbService.SourceBranch),
				SourceSha:    pulumi.String(rsbService.SourceCommit),
				Branch:       pulumi.String(env.Name),
				Repository:   pulumi.String(rsbService.Name),
			}, pulumi.DeleteBeforeReplace(true), pulumi.Provider(githubProvider))
			if err != nil {
				return fmt.Errorf("creating branch [%s]: %w", rsbService.Name, err)
			}

			tg, err := elasticloadbalancingv2.NewTargetGroup(ctx, fmt.Sprintf("tg-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.TargetGroupArgs{
				Name:       pulumi.Sprintf(shortEnvName(env.Name, rsbService.Name)),
				TargetType: pulumi.String("ip"),
				Protocol:   pulumi.String("HTTP"),
				Port:       pulumi.Int(80),
				VpcId:      vpc.ID(),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating elb target group [%s]: %w", rsbService.Name, err)
			}

			serviceLoadBalancers := ecs.ServiceLoadBalancerArray{
				ecs.ServiceLoadBalancerArgs{
					TargetGroupArn: tg.Arn,
					ContainerName:  pulumi.String(rsbService.Name),
					ContainerPort:  pulumi.Int(80),
				},
			}

			randomOrder, err := random.NewRandomInteger(ctx, fmt.Sprintf("random-order-%s-%s", rsbService.Name, env.Name), &random.RandomIntegerArgs{
				Min: pulumi.Int(1),
				Max: pulumi.Int(999),
			})
			if err != nil {
				return fmt.Errorf("creating random order integer [%s]: %w", rsbService.Name, err)
			}

			randomPriority, err := random.NewRandomInteger(ctx, fmt.Sprintf("random-priority-%s-%s", rsbService.Name, env.Name), &random.RandomIntegerArgs{
				Min: pulumi.Int(1),
				Max: pulumi.Int(4095),
			})
			if err != nil {
				return fmt.Errorf("creating random priority integer [%s]: %w", rsbService.Name, err)
			}

			_, err = elasticloadbalancingv2.NewListenerRule(ctx, fmt.Sprintf("rule-http-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.ListenerRuleArgs{
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
								pulumi.Sprintf("%s.services.%s.%s", shortName(rsbService.Name), env.Name, env.AwsServices.Route53.Domain),
							},
						},
					},
				},
				Priority: randomPriority.Result,
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating elb http listener rule [%s]: %w", rsbService.Name, err)
			}

			_, err = elasticloadbalancingv2.NewListenerRule(ctx, fmt.Sprintf("rule-https-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.ListenerRuleArgs{
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
								pulumi.Sprintf("%s.services.%s.%s", shortName(rsbService.Name), env.Name, env.AwsServices.Route53.Domain),
							},
						},
					},
				},
				Priority: randomPriority.Result,
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating elb https listener rule [%s]: %w", rsbService.Name, err)
			}

			serviceRecord, err := route53.NewRecord(ctx, fmt.Sprintf("record-https-%s-%s", rsbService.Name, env.Name), &route53.RecordArgs{
				Name: pulumi.Sprintf("%s.services.%s.%s.", shortName(rsbService.Name), env.Name, env.AwsServices.Route53.Domain),
				Type: route53.RecordTypeCNAME,
				Records: pulumi.StringArray{
					lbMain.DnsName,
				},
				ZoneId: pulumi.String(env.AwsServices.Route53.DNSZoneID),
				Ttl:    pulumi.Int(300),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating record [%s]: %w", rsbService.Name, err)
			}

			serviceRecords[rsbService.Name] = serviceRecord.Fqdn

			if _apiGWServices[rsbService.Name] {
				nlb, err := elasticloadbalancingv2.NewLoadBalancer(ctx, fmt.Sprintf("lb-network-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.LoadBalancerArgs{
					Name:             pulumi.String(shortEnvName(env.Name, rsbService.Name)),
					LoadBalancerType: pulumi.String("network"),
					Internal:         pulumi.Bool(true),
					Subnets: pulumi.StringArray{
						subnetGroups[_subnetGroupPublic][0].ID(),
						subnetGroups[_subnetGroupPublic][1].ID(),
						subnetGroups[_subnetGroupPublic][2].ID(),
					},
				}, pulumi.Provider(awsProvider))
				if err != nil {
					return fmt.Errorf("creating network load balancer [%s]: %w", rsbService.Name, err)
				}

				tgNLB, err := elasticloadbalancingv2.NewTargetGroup(ctx, fmt.Sprintf("nlb-tcp-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.TargetGroupArgs{
					Name:       pulumi.Sprintf("%s-nlb", shortEnvName(env.Name, rsbService.Name)),
					TargetType: pulumi.String("ip"),
					Protocol:   pulumi.String("TCP"),
					Port:       pulumi.Int(80),
					VpcId:      vpc.ID(),
				}, pulumi.Provider(awsProvider))
				if err != nil {
					return fmt.Errorf("creating nlb target group [%s]: %w", rsbService.Name, err)
				}

				serviceLoadBalancers = append(serviceLoadBalancers, ecs.ServiceLoadBalancerArgs{
					TargetGroupArn: tgNLB.Arn,
					ContainerName:  pulumi.String(rsbService.Name),
					ContainerPort:  pulumi.Int(80),
				})

				_, err = elasticloadbalancingv2.NewListener(ctx, fmt.Sprintf("nlb-listener-http-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.ListenerArgs{
					LoadBalancerArn: nlb.Arn,
					Protocol:        pulumi.String("TCP"),
					Port:            pulumi.Int(80),
					DefaultActions: elasticloadbalancingv2.ListenerDefaultActionArray{
						elasticloadbalancingv2.ListenerDefaultActionArgs{
							Type:           pulumi.String("forward"),
							TargetGroupArn: tgNLB.Arn,
						},
					},
				}, pulumi.Provider(awsProvider))
				if err != nil {
					return fmt.Errorf("creating nlb http listener [%s]: %w", rsbService.Name, err)
				}

				_, err = elasticloadbalancingv2.NewListener(ctx, fmt.Sprintf("nlb-listener-https-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.ListenerArgs{
					LoadBalancerArn: nlb.Arn,
					Protocol:        pulumi.String("TLS"),
					Port:            pulumi.Int(443),
					CertificateArn:  certValidationServicesWildcard.CertificateArn,
					DefaultActions: elasticloadbalancingv2.ListenerDefaultActionArray{
						elasticloadbalancingv2.ListenerDefaultActionArgs{
							Type:           pulumi.String("forward"),
							TargetGroupArn: tgNLB.Arn,
						},
					},
				}, pulumi.Provider(awsProvider))
				if err != nil {
					return fmt.Errorf("creating nlb https listener [%s]: %w", rsbService.Name, err)
				}

				vpcLink, err := apigateway.NewVpcLink(ctx, fmt.Sprintf("vpc-link-%s-%s", rsbService.Name, env.Name), &apigateway.VpcLinkArgs{
					Name:      pulumi.Sprintf("%s-%s", env.Name, rsbService.Name),
					TargetArn: nlb.Arn,
				}, pulumi.Provider(awsProvider))
				if err != nil {
					return fmt.Errorf("creating vpc link [%s]: %w", rsbService.Name, err)
				}

				vpcLinkIDs[rsbService.Name] = vpcLink.ID()
			}

			containerDefinitions := pulumi.All(
				branch.Branch,
				repo.RepositoryUrl,
				elc.CacheNodes.Index(pulumi.Int(0)).Address(),
				apigw.ID().ToStringOutput(),
				rsbService.Name,
				dbMasterUserPassword,
				rmqMasterUserPassword,
				bastionPrivRecord.Fqdn,
				esEndpoint,
			).ApplyT(func(args []interface{}) (string, error) {
				rsbServiceName := args[4].(string)

				baseTaskDef, err := fetchFileFromGithubRepo(cred.GithubOrgName, rsbServiceName, env.Name, "BaseTaskDefinition.json", cred.GithubAuthToken)
				if err != nil {
					return "", fmt.Errorf("fetch base task def [%s]: %w", rsbServiceName, err)
				}

				var containerDefinitions = struct {
					Definitions []map[string]interface{} `json:"containerDefinitions"`
				}{}

				err = json.Unmarshal([]byte(baseTaskDef), &containerDefinitions)
				if err != nil {
					return "", fmt.Errorf("unmarshal base task def [%s]: %w", rsbServiceName, err)
				}

				containerDefinitions.Definitions[0]["name"] = rsbServiceName
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

				svcShortName := shortName(rsbServiceName)
				elcHostname := args[2].(*string)
				apigwID := args[3].(string)
				dbMasterUserPassword := args[5].(string)
				rmqMasterUserPassword := args[6].(string)
				bastionPrivURL := args[7].(string)
				esEndpoint := args[8].(string)

				mappings := map[string]string{
					// Bastion
					"REPLACEME_BASTION_HOST": bastionPrivURL,

					// Api Gateway
					"REPLACEME_AWS_API_GW_ID": apigwID,

					// RSB Services base URL
					"REPLACEME_RSB_API_BASE_URL":                fmt.Sprintf("https://%s.execute-api.eu-west-1.amazonaws.com/v1", apigwID),
					"REPLACEME_SERVICE_REGISTRY_BASE_URL":       fmt.Sprintf("https://servicerepository.services.%s.%s", env.Name, env.AwsServices.Route53.Domain),
					"REPLACEME_VENTURE_CONFIG_SERVICE_BASE_URL": fmt.Sprintf("https://ventureconfig.services.%s.%s", env.Name, env.AwsServices.Route53.Domain),
					"REPLACEME_FEEDER_URL":                      fmt.Sprintf("https://feeder.services.%s.%s", env.Name, env.AwsServices.Route53.Domain),
					"REPLACEME_USER_SERVICE_BASE_URL":           fmt.Sprintf("https://users.services.%s.%s", env.Name, env.AwsServices.Route53.Domain),
					// "REPLACEME_E2EMON_BASE_URL":                  e2eMonBaseUrl(),

					// RSB Services configs
					"REPLACEME_VENTURE_CONFIG_SERVICE_CACHE_TAG": fmt.Sprintf("rsb_vc_%s", env.Name),
					"REPLACEME_BACKUP_INTERVAL":                  "5",
					"REPLACEME_RSBServicesCORSOriginURLs":        fmt.Sprintf("%s,https://admin-ui.services.%s.%s", env.RsbServices.CORSOriginURLs, env.Name, env.AwsServices.Route53.Domain),

					// Message brokers
					"REPLACEME_MESSAGE_BROKER_DRIVER": env.RsbServices.Broker.Driver,
					"REPLACEME_RMQServer":             bastionPrivURL,
					"REPLACEME_RMQMasterUsername":     env.RsbServices.Broker.Username,
					"REPLACEME_RMQMasterUserPassword": rmqMasterUserPassword,
					"REPLACEME_RMQAdminURL":           fmt.Sprintf("http://%s:%d", bastionPrivURL, env.RsbServices.Broker.AdminPort),
					// "REPLACEME_RMQVHost":                         env.RMQVHost,
					"REPLACEME_MqAMQPPort":        strconv.Itoa(env.RsbServices.Broker.Port),
					"REPLACEME_MqRabbitAdminPort": strconv.Itoa(env.RsbServices.Broker.AdminPort),
					"REPLACEME_MqProtocol":        "amqp",

					// Databases
					// "REPLACEME_DB_HOST":                          env.DBHostname,
					// "REPLACEME_DBHostname":                       env.DBHostname,
					"REPLACEME_DBMasterUsername":     env.AwsServices.RDS.Username,
					"REPLACEME_DBMasterUserPassword": dbMasterUserPassword,
					"REPLACEME_DB_DATABASE":          fmt.Sprintf("%s_%s", env.Name, svcShortName),
					"REPLACEME_LibDBTable":           fmt.Sprintf("%s_%s", env.Name, svcShortName),

					// AWS credentials
					"REPLACEME_AwsAccessKeyID":     cred.AWSAccessKeyID,
					"REPLACEME_AwsSecretAccessKey": cred.AWSSecretAccessKey,
					"REPLACEME_AwsRegion":          cred.AWSRegion,

					// Github credentials
					"REPLACEME_GithubOrgname":    cred.GithubOrgName,
					"REPLACEME_GithubOauthToken": cred.GithubAuthToken,

					// Route 53
					"REPLACEME_DNSZoneID": env.AwsServices.Route53.DNSZoneID,
					"REPLACEME_Domain":    env.AwsServices.Route53.Domain,

					// Slack
					"REPLACEME_SLACK_WEBHOOK": env.SlackWebHook,

					// Elastic Cache
					"REPLACEME_ElasticacheHostname": *elcHostname,

					// Elastic Search
					"REPLACEME_ELASTICSEARCH_URL":          fmt.Sprintf("https://%s", esEndpoint),
					"REPLACEME_SERVICE_REGISTRY_CACHE_TAG": fmt.Sprintf("rsb_sr_%s", env.Name),

					// Datadog
					"REPLACEME_DATADOG_ENABLED":      fmt.Sprintf("%t", env.ThirdPartyServices.DataDog.Enabled),
					"REPLACEME_DATADOG_API_BASE_URL": env.ThirdPartyServices.DataDog.ApiBaseURL,
					"REPLACEME_DATADOG_API_KEY":      env.ThirdPartyServices.DataDog.ApiKey,
					"REPLACEME_DATADOG_APP_KEY":      env.ThirdPartyServices.DataDog.AppKey,

					// Misc
					"REPLACEME_RSB_ENV":      env.Name,
					"REPLACEME_RELEASE_NAME": env.Name,
				}

				environments, ok := containerDefinitions.Definitions[0]["environment"].([]interface{})
				if !ok {
					return "", fmt.Errorf("unexpected environments type [%s]", rsbServiceName)
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
					return "", fmt.Errorf("marshal base task def [%s]: %w", rsbServiceName, err)
				}

				return string(jsonB), nil
			}).(pulumi.StringOutput)

			taskDef, err := ecs.NewTaskDefinition(ctx, fmt.Sprintf("task-def-%s-%s", rsbService.Name, env.Name), &ecs.TaskDefinitionArgs{
				ContainerDefinitions: containerDefinitions,
				Family:               pulumi.Sprintf("%s-%s", env.Name, rsbService.Name),
				ExecutionRoleArn:     roleExecution.Arn,
				NetworkMode:          pulumi.String("awsvpc"),
				Cpu:                  pulumi.String(strconv.Itoa(env.AwsServices.ECS.CPU)),
				Memory:               pulumi.String(strconv.Itoa(env.AwsServices.ECS.Memory)),
				RequiresCompatibilities: pulumi.StringArray{
					pulumi.String("FARGATE"),
				},
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating task definition [%s]: %w", rsbService.Name, err)
			}

			ecsService, err := ecs.NewService(ctx, fmt.Sprintf("ecs-service-%s-%s", rsbService.Name, env.Name), &ecs.ServiceArgs{
				Cluster:        cluster.ID(),
				Name:           pulumi.String(rsbService.Name),
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
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating ecs service [%s]: %w", rsbService.Name, err)
			}

			cb, err := codebuild.NewProject(ctx, fmt.Sprintf("cb-project-%s-%s", rsbService.Name, env.Name), &codebuild.ProjectArgs{
				Artifacts: codebuild.ProjectArtifactsArgs{
					Type: pulumi.String("NO_ARTIFACTS"),
				},
				Description: pulumi.Sprintf("Build project for %s in %s", rsbService.Name, env.Name),
				Environment: codebuild.ProjectEnvironmentArgs{
					ComputeType:              pulumi.String("BUILD_GENERAL1_SMALL"),
					Image:                    pulumi.String("aws/codebuild/standard:5.0"),
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
							Value: pulumi.String(env.AwsServices.Route53.Domain),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_BASTION_HOST"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.Sprintf("srv.%s.%s", env.Name, env.AwsServices.Route53.Domain),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_ENV_BASTION_URL"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.Sprintf("http://bastion.%s.%s", env.Name, env.AwsServices.Route53.Domain),
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
				Name: pulumi.Sprintf("%s_%s", env.Name, rsbService.Name),
				Cache: &codebuild.ProjectCacheArgs{
					Modes: pulumi.StringArray{
						pulumi.String("LOCAL_SOURCE_CACHE"),
						pulumi.String("LOCAL_DOCKER_LAYER_CACHE"),
					},
					Type: pulumi.String("LOCAL"),
				},
				ServiceRole: roleBuildpipeline.Arn,
				Source: &codebuild.ProjectSourceArgs{
					GitCloneDepth: pulumi.Int(1),
					Location:      pulumi.Sprintf("https://github.com/%s/%s.git", cred.GithubOrgName, rsbService.Name),
					Type:          pulumi.String("GITHUB"),
				},
				SourceVersion: pulumi.String(env.Name),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating codebuild project [%s]: %w", rsbService.Name, err)
			}

			_, err = codepipeline.NewPipeline(ctx, fmt.Sprintf("code-pipeline-%s-%s", rsbService.Name, env.Name), &codepipeline.PipelineArgs{
				ArtifactStore: codepipeline.PipelineArtifactStoreArgs{
					Location: bucketArtifacts.Bucket,
					Type:     pulumi.String("S3"),
				},
				Name:    pulumi.Sprintf("%s@%s", rsbService.Name, env.Name),
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
									"Repo":                 pulumi.String(rsbService.Name),
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
									"ProjectName": pulumi.Sprintf("%s_%s", env.Name, rsbService.Name),
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
									"ServiceName": pulumi.String(rsbService.Name),
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
			}, pulumi.DependsOn([]pulumi.Resource{ecsService, cb}), pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("creating code pipeline [%s]: %w", rsbService.Name, err)
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
			ConnectionId:          vpcLinkIDs["rsb-service-feeder"],
			RequestParameters: pulumi.StringMap{
				"integration.request.header.x-api-key": pulumi.String("method.request.header.x-api-key"),
			},
			Uri: pulumi.Sprintf("https://feeder.services.%s.%s/api/events", env.Name, env.AwsServices.Route53.Domain),
		}, pulumi.Provider(awsProvider))
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
			ConnectionId:          vpcLinkIDs["rsb-service-users"],
			Uri:                   pulumi.Sprintf("https://users.services.%s.%s/api/login", env.Name, env.AwsServices.Route53.Domain),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating rest api gw integration login: %w", err)
		}

		_, err = apigateway.NewDeployment(ctx, "api-gw-deployment-"+env.Name, &apigateway.DeploymentArgs{
			RestApi:          apigw.ID(),
			StageName:        pulumi.String("v1"),
			StageDescription: pulumi.String("v1"),
			Description:      pulumi.String("Init"),
		}, pulumi.DependsOn([]pulumi.Resource{integEvents, integLogin}), pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("creating rest api gw stage: %w", err)
		}

		result := pulumi.Map{
			"name":                  pulumi.String(env.Name),
			"broker_server":         bastionPrivRecord.Fqdn,
			"broker_admin_ui":       pulumi.Sprintf("%s:%d", bastionPubRecord.Fqdn, env.RsbServices.Broker.AdminPort),
			"broker_username":       pulumi.String(env.RsbServices.Broker.Username),
			"broker_admin_password": rmqMasterUserPassword,
			"services_routes":       serviceRecords,
			"slack_webhook":         pulumi.String(env.SlackWebHook),
			"loadbalancer":          lbMain.DnsName,
			"domain":                pulumi.String(env.AwsServices.Route53.Domain),
		}

		if env.AwsServices.RDS.Enabled {
			result["db_password"] = dbMasterUserPassword
		}

		ctx.Export("result", result)

		return nil
	}
}
