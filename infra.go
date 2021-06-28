package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/avelino/slugify"
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
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/lambda"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/resourcegroups"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/route53"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/s3"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/sns"
	"github.com/pulumi/pulumi-cloudamqp/sdk/v3/go/cloudamqp"
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

func infra(env environment) pulumi.RunFunc {
	return func(ctx *pulumi.Context) error {
		githubProvider, err := github.NewProvider(ctx, "provider-github-"+env.Name, &github.ProviderArgs{
			Owner: pulumi.String(env.GithubOrgName),
			Token: pulumi.String(env.GithubAuthToken),
		})
		if err != nil {
			return fmt.Errorf("new github provider: %w", err)
		}

		awsProvider, err := aws.NewProvider(ctx, "provider-aws-"+env.Name, &aws.ProviderArgs{
			AccessKey: pulumi.String(env.AWSAccessKeyID),
			SecretKey: pulumi.String(env.AWSSecretAccessKey),
			Region:    pulumi.String(env.AWSRegion),
			DefaultTags: aws.ProviderDefaultTagsArgs{
				Tags: pulumi.StringMap{
					"RSB_ENV": pulumi.String(env.Name),
					"Name":    pulumi.String(env.Name),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("new aws provider: %w", err)
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
			return fmt.Errorf("new resource group: %w", err)
		}

		// VPC
		vpc, err := ec2.NewVpc(ctx, "vpc-"+env.Name, &ec2.VpcArgs{
			CidrBlock:                    pulumi.String("10.15.96.0/19"),
			AssignGeneratedIpv6CidrBlock: pulumi.Bool(true),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new vpc: %w", err)
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
				return fmt.Errorf("new vpc subnet [%s]: %w", name, err)
			}

			subnetGroups[subnet.Group] = append(subnetGroups[subnet.Group], sbnt)
		}

		// Internet Gateway
		igw, err := ec2.NewInternetGateway(ctx, "igw-"+env.Name, &ec2.InternetGatewayArgs{
			VpcId: vpc.ID(),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new internet gateway: %w", err)
		}

		// Elastic IP
		eip, err := ec2.NewEip(ctx, "eip-"+env.Name, &ec2.EipArgs{}, pulumi.DependsOn([]pulumi.Resource{igw}), pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new elastic ip: %w", err)
		}

		// NAT Gateway
		nat, err := ec2.NewNatGateway(ctx, "nat-"+env.Name, &ec2.NatGatewayArgs{
			AllocationId: eip.ID(),
			SubnetId:     subnetGroups[_subnetGroupPublic][0].ID(),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new internet gateway: %w", err)
		}

		// Route tables
		routeTables := make(map[string]*ec2.RouteTable)
		for groupName, subnets := range subnetGroups {
			routeTableName := "rt-" + env.Name + "-" + groupName
			rt, err := ec2.NewRouteTable(ctx, routeTableName, &ec2.RouteTableArgs{
				VpcId: vpc.ID(),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new route table [%s]: %w", routeTableName, err)
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
				return fmt.Errorf("new default route [%s]: %w", routeName, err)
			}

			// Route table assiociations
			for i, subnet := range subnets {
				routeAssocName := fmt.Sprintf("rt-assoc-%s-%s-%d", env.Name, groupName, i)
				_, err = ec2.NewRouteTableAssociation(ctx, routeAssocName, &ec2.RouteTableAssociationArgs{
					RouteTableId: rt.ID(),
					SubnetId:     subnet.ID(),
				}, pulumi.Provider(awsProvider))
				if err != nil {
					return fmt.Errorf("new route table assiociation [%s]: %w", routeAssocName, err)
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
			return fmt.Errorf("new security group: %w", err)
		}

		// Certificate for services
		certServices, err := acm.NewCertificate(ctx, "cert-services-"+env.Name, &acm.CertificateArgs{
			DomainName:       pulumi.Sprintf("*.services.%s.%s", env.Name, env.AwsServices.Route53.Domain),
			ValidationMethod: pulumi.String("DNS"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new cert for services: %w", err)
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
			return fmt.Errorf("new record for cert validation for services: %w", err)
		}

		// Request certificate validation for services
		certValidationServicesWildcard, err := acm.NewCertificateValidation(ctx, "cert-services-validation-"+env.Name, &acm.CertificateValidationArgs{
			CertificateArn: certServices.Arn,
			ValidationRecordFqdns: pulumi.StringArray{
				recordCertServices.Fqdn,
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new cert validation for services: %w", err)
		}

		// Certificate for wildcard
		certWildcard, err := acm.NewCertificate(ctx, "cert-wildcard-"+env.Name, &acm.CertificateArgs{
			DomainName:       pulumi.Sprintf("*.%s.%s", env.Name, env.AwsServices.Route53.Domain),
			ValidationMethod: pulumi.String("DNS"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new cert for wildcard: %w", err)
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
			return fmt.Errorf("new record for cert validation for wildcard: %w", err)
		}

		// Request certificate validation for wildcard
		certValidationWildcard, err := acm.NewCertificateValidation(ctx, "cert-wildcard-validation-"+env.Name, &acm.CertificateValidationArgs{
			CertificateArn: certWildcard.Arn,
			ValidationRecordFqdns: pulumi.StringArray{
				recordCertWildcard.Fqdn,
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new cert validation for wildcard: %w", err)
		}

		var dbMasterUserPassword pulumi.StringInput
		if env.AwsServices.RDS.Enabled {
			ctx.Log.Warn("RDS not provisioned: not implemented: not used.", nil)

			if env.AwsServices.RDS.Password == "" {
				dbMasterUserPasswordGenerated, err := random.NewRandomPassword(ctx, "password-db-master-user-password-"+env.Name, &random.RandomPasswordArgs{
					Length:  pulumi.Int(32),
					Lower:   pulumi.Bool(true),
					Upper:   pulumi.Bool(true),
					Special: pulumi.Bool(false),
				})
				if err != nil {
					return fmt.Errorf("new db master user password: %w", err)
				}

				dbMasterUserPassword = dbMasterUserPasswordGenerated.Result
			} else {
				dbMasterUserPassword = pulumi.String(env.AwsServices.RDS.Password)
			}
		} else {
			ctx.Log.Warn("RDS not provisioned: disabled.", nil)

			dbMasterUserPassword = pulumi.String("")
		}

		var rmqMasterUserPassword pulumi.StringInput
		if env.RsbServices.Broker.Password == "" {
			rmqMasterUserPasswordGenerated, err := random.NewRandomPassword(ctx, "password-rmq-master-user-password-"+env.Name, &random.RandomPasswordArgs{
				Length:  pulumi.Int(32),
				Lower:   pulumi.Bool(true),
				Upper:   pulumi.Bool(true),
				Special: pulumi.Bool(false),
			})
			if err != nil {
				return fmt.Errorf("new rmq master user password: %w", err)
			}

			rmqMasterUserPassword = rmqMasterUserPasswordGenerated.Result
		} else {
			rmqMasterUserPassword = pulumi.String(env.RsbServices.Broker.Password)
		}

		UserDataBase64 := pulumi.All(dbMasterUserPassword, rmqMasterUserPassword).ApplyT(func(args []interface{}) string {
			return base64.StdEncoding.EncodeToString(
				[]byte(fmt.Sprintf("#!/bin/bash\ncd /root\nprintf \"\\nmachine github.com\nlogin roam\npassword %s\" >> .netrc\ngit clone https://github.com/RingierIMU/rsb-deploy.git\necho -n \"%s\" > RMQMasterUserPassword\necho -n \"%s\" > DBMasterUserPassword\necho -n \"%s\" > RSB_Env\necho -n \"%s\" > SLACK_WEBHOOK\ncd ./rsb-deploy/aws/bastion/\n./setup.sh", env.GithubAuthToken, args[1].(string), args[0].(string), env.Name, env.SlackWebHook)),
			)
		}).(pulumi.StringOutput)

		// Bastion instance
		// FIXME: perpetual diff for EbsBlockDevices so using default with AMI
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
			return fmt.Errorf("new ec2 instance for bastion: %w", err)
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
			return fmt.Errorf("new public A record for bastion: %w", err)
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
			return fmt.Errorf("new private A record for bastion: %w", err)
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
				return fmt.Errorf("new bastion route [%s]: %w", routeName, err)
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
			return fmt.Errorf("new elastic subnet group: %w", err)
		}

		// Elastic search
		var esEndpoint pulumi.StringInput
		if env.AwsServices.ES.Enabled {
			// _, err = iam.NewServiceLinkedRole(ctx, "es-iam-slr-"+env.Name, &iam.ServiceLinkedRoleArgs{
			// 	AwsServiceName: pulumi.String("es.amazonaws.com"),
			// })
			// if err != nil {
			// 	return fmt.Errorf("new elastic search iam service linked role: %w", err)
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
				return fmt.Errorf("new elastic search domain: %w", err)
			}

			esEndpoint = es.Endpoint
		} else {
			ctx.Log.Warn("ES not provisioned: disabled.", nil)

			esEndpoint = pulumi.String("")
		}

		// CloudAMQP
		var (
			brokerDriver    pulumi.StringInput
			brokerProtocol  pulumi.StringInput
			brokerVhost     pulumi.StringInput
			brokerServer    pulumi.StringInput
			brokerPort      pulumi.IntInput
			brokerAdminPort pulumi.IntInput
			brokerAdminURL  pulumi.StringInput
			brokerUsername  pulumi.StringInput
			brokerPassword  pulumi.StringInput
		)
		if env.ThirdPartyServices.CloudAMQP.CustomerApiKey != "" {
			cloudAMQPProvider, err := cloudamqp.NewProvider(ctx, "provider-cloudamqp-"+env.Name, &cloudamqp.ProviderArgs{
				Apikey: pulumi.String(env.ThirdPartyServices.CloudAMQP.CustomerApiKey),
			})
			if err != nil {
				return fmt.Errorf("new cloudamqp provider: %w", err)
			}

			cloudAMQPInstance, err := cloudamqp.NewInstance(ctx, "cloudamqp-instance-"+env.Name, &cloudamqp.InstanceArgs{
				Name:      pulumi.String(env.ThirdPartyServices.CloudAMQP.InstanceName),
				Nodes:     pulumi.Int(env.ThirdPartyServices.CloudAMQP.InstanceNodes),
				Plan:      pulumi.String(env.ThirdPartyServices.CloudAMQP.InstanceType),
				Region:    pulumi.String(env.ThirdPartyServices.CloudAMQP.InstanceRegion),
				VpcSubnet: pulumi.String(env.ThirdPartyServices.CloudAMQP.InstanceSubnet),
				Tags: pulumi.StringArray{
					pulumi.String(env.Name),
				},
			}, pulumi.Provider(cloudAMQPProvider))
			if err != nil {
				return fmt.Errorf("new cloudamqp instance: %w", err)
			}

			// Convert instanceID to IntOutput
			instanceID := cloudAMQPInstance.ID().ApplyT(func(id string) (int, error) {
				instanceID, err := strconv.Atoi(id)
				if err != nil {
					return 0, fmt.Errorf("convert cloudamqp instance id from string to int: %w", err)
				}

				return instanceID, nil

			}).(pulumi.IntOutput)

			// CloudAMQP - Extract vpc information
			cloudAMQPInstanceVPCInfo := instanceID.ApplyT(func(id int) (map[string]string, error) {
				vpcInfo, err := cloudamqp.GetVpcInfo(ctx, &cloudamqp.GetVpcInfoArgs{
					InstanceId: id,
				}, pulumi.Provider(cloudAMQPProvider))
				if err != nil {
					return nil, fmt.Errorf("get cloud amqp vpc info: %w", err)
				}

				return map[string]string{
					"owner_id":   vpcInfo.OwnerId,
					"vpc_id":     vpcInfo.Id,
					"vpc_subnet": vpcInfo.VpcSubnet,
				}, nil

			}).(pulumi.StringMapOutput)

			//  AWS - Create peering request
			vpcPeerConn, err := ec2.NewVpcPeeringConnection(ctx, "vpc-peer-conn-cloud-amqp"+env.Name, &ec2.VpcPeeringConnectionArgs{
				PeerOwnerId: cloudAMQPInstanceVPCInfo.MapIndex(pulumi.String("owner_id")),
				PeerVpcId:   cloudAMQPInstanceVPCInfo.MapIndex(pulumi.String("vpc_id")),
				VpcId:       vpc.ID(),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new vpc peering connection: %w", err)
			}

			//  CloudAMQP - accept the peering request
			_, err = cloudamqp.NewVpcPeering(ctx, "cloudamqp-vpc-peering-"+env.Name, &cloudamqp.VpcPeeringArgs{
				InstanceId: instanceID,
				PeeringId:  vpcPeerConn.ID(),
			}, pulumi.Provider(cloudAMQPProvider))
			if err != nil {
				return fmt.Errorf("new cloudamqp vpc peering: %w", err)
			}

			_, err = ec2.NewRoute(ctx, "route-vpc-peering-priv-"+env.Name, &ec2.RouteArgs{
				RouteTableId:           routeTables["rt-"+env.Name+"-"+_subnetGroupPrivate].ID(),
				DestinationCidrBlock:   cloudAMQPInstanceVPCInfo.MapIndex(pulumi.String("vpc_subnet")),
				VpcPeeringConnectionId: vpcPeerConn.ID(),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new route vpc peering private: %w", err)
			}

			_, err = ec2.NewRoute(ctx, "route-vpc-peering-pub-"+env.Name, &ec2.RouteArgs{
				RouteTableId:           routeTables["rt-"+env.Name+"-"+_subnetGroupPublic].ID(),
				DestinationCidrBlock:   cloudAMQPInstanceVPCInfo.MapIndex(pulumi.String("vpc_subnet")),
				VpcPeeringConnectionId: vpcPeerConn.ID(),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new route vpc peering public: %w", err)
			}

			brokerDriver = pulumi.String("rabbitmq")
			brokerProtocol = pulumi.String("amqps")
			brokerVhost = pulumi.String(env.Name)
			brokerPort = pulumi.Int(5672)
			brokerAdminPort = pulumi.Int(15672)

			brokerServer = cloudAMQPInstance.Url.ApplyT(func(rawURL string) string {
				parsedURL, _ := url.Parse(rawURL)
				return strings.Replace(parsedURL.Hostname(), ".rmq.", ".in.", 1)
			}).(pulumi.StringOutput)

			brokerUsername = cloudAMQPInstance.Url.ApplyT(func(rawURL string) string {
				parsedURL, _ := url.Parse(rawURL)
				return parsedURL.User.Username()
			}).(pulumi.StringOutput)

			brokerPassword = cloudAMQPInstance.Url.ApplyT(func(rawURL string) string {
				parsedURL, _ := url.Parse(rawURL)
				password, _ := parsedURL.User.Password()
				return password
			}).(pulumi.StringOutput)
		} else {
			ctx.Log.Warn("CloudAMQP not provisioned: check CustomerApiKey.", nil)

			brokerDriver = pulumi.String(env.RsbServices.Broker.Driver)
			brokerProtocol = pulumi.String("amqp")
			brokerVhost = pulumi.String("")
			brokerPort = pulumi.Int(env.RsbServices.Broker.Port)
			brokerAdminPort = pulumi.Int(env.RsbServices.Broker.AdminPort)

			brokerServer = bastionPrivRecord.Fqdn
			brokerUsername = pulumi.String(env.RsbServices.Broker.Username)
			brokerPassword = rmqMasterUserPassword

			brokerAdminURL = pulumi.Sprintf("http://%s:%d", bastionPrivRecord.Fqdn, env.RsbServices.Broker.AdminPort)
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
			return fmt.Errorf("new elastic cluster: %w", err)
		}

		// API GW
		apigw, err := apigateway.NewRestApi(ctx, "api-gw-"+env.Name, &apigateway.RestApiArgs{
			Name: pulumi.String(env.Name),
			EndpointConfiguration: apigateway.RestApiEndpointConfigurationArgs{
				Types: pulumi.String("REGIONAL"),
			},
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw: %w", err)
		}

		resEvents, err := apigateway.NewResource(ctx, "api-gw-res-events-"+env.Name, &apigateway.ResourceArgs{
			RestApi:  apigw.ID(),
			ParentId: apigw.RootResourceId,
			PathPart: pulumi.String("events"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw resource events: %w", err)
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
			return fmt.Errorf("new rest api gw method events: %w", err)
		}

		resLogin, err := apigateway.NewResource(ctx, "api-gw-res-login-"+env.Name, &apigateway.ResourceArgs{
			RestApi:  apigw.ID(),
			ParentId: apigw.RootResourceId,
			PathPart: pulumi.String("login"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw resource login: %w", err)
		}

		methodLogin, err := apigateway.NewMethod(ctx, "api-gw-method-login-"+env.Name, &apigateway.MethodArgs{
			RestApi:        apigw.ID(),
			ResourceId:     resLogin.ID(),
			ApiKeyRequired: pulumi.Bool(false),
			HttpMethod:     pulumi.String("POST"),
			Authorization:  pulumi.String("NONE"),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw method login: %w", err)
		}

		domainAPIGw, err := apigateway.NewDomainName(ctx, "api-gw-domain-"+env.Name, &apigateway.DomainNameArgs{
			DomainName: pulumi.Sprintf("bus.%s.%s", env.Name, env.AwsServices.Route53.Domain),
			EndpointConfiguration: apigateway.DomainNameEndpointConfigurationArgs{
				Types: pulumi.String("REGIONAL"),
			},
			RegionalCertificateArn: certValidationWildcard.CertificateArn,
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw domain: %w", err)
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
			return fmt.Errorf("new record for cert validation for wildcard: %w", err)
		}

		_, err = apigateway.NewBasePathMapping(ctx, "api-gw-path-"+env.Name, &apigateway.BasePathMappingArgs{
			DomainName: domainAPIGw.DomainName,
			RestApi:    apigw.ID(),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw base path mapping: %w", err)
		}

		// ECS Cluster
		cluster, err := ecs.NewCluster(ctx, "ecs-cluster-"+env.Name, &ecs.ClusterArgs{
			Name: pulumi.String(env.Name),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new ecs cluster: %w", err)
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
			return fmt.Errorf("new role task exec ecs cluster: %w", err)
		}

		bucketArtifacts, err := s3.NewBucket(ctx, "bucket-codepipeline-"+env.Name, &s3.BucketArgs{
			Bucket:       pulumi.Sprintf("%s-ci-cd-artifacts", env.Name),
			ForceDestroy: pulumi.Bool(true),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new bucket codepipeline: %w", err)
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
			return fmt.Errorf("new role codepipeline: %w", err)
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
			return fmt.Errorf("new role buildpipeline: %w", err)
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
			return fmt.Errorf("new main load balancer: %w", err)
		}

		tgDefault, err := elasticloadbalancingv2.NewTargetGroup(ctx, "elb-target-group-default-"+env.Name, &elasticloadbalancingv2.TargetGroupArgs{
			Name:       pulumi.Sprintf("%s-default", env.Name),
			TargetType: pulumi.String("ip"),
			Protocol:   pulumi.String("HTTP"),
			Port:       pulumi.Int(80),
			VpcId:      vpc.ID(),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new elb default target group: %w", err)
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
			return fmt.Errorf("new elb http listener: %w", err)
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
			return fmt.Errorf("new elb https listener: %w", err)
		}

		vpcLinkIDs := make(pulumi.StringMap)
		serviceRecords := make(pulumi.StringMap)
		for _, rsbService := range env.RsbServices.Services {
			repo, err := ecr.NewRepository(ctx, fmt.Sprintf("repo-%s-%s", rsbService.Name, env.Name), &ecr.RepositoryArgs{
				Name: pulumi.Sprintf("%s/%s", env.Name, rsbService.Name),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new repo [%s]: %w", rsbService.Name, err)
			}

			branch, err := github.NewBranch(ctx, fmt.Sprintf("branch-%s-%s", rsbService.Name, env.Name), &github.BranchArgs{
				SourceBranch: pulumi.String(rsbService.SourceBranch),
				SourceSha:    pulumi.String(rsbService.SourceCommit),
				Branch:       pulumi.String(env.Name),
				Repository:   pulumi.String(rsbService.Name),
			}, pulumi.DeleteBeforeReplace(true), pulumi.Provider(githubProvider))
			if err != nil {
				return fmt.Errorf("new branch [%s]: %w", rsbService.Name, err)
			}

			tg, err := elasticloadbalancingv2.NewTargetGroup(ctx, fmt.Sprintf("tg-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.TargetGroupArgs{
				Name:       pulumi.Sprintf(shortEnvName(env.Name, rsbService.Name)),
				TargetType: pulumi.String("ip"),
				Protocol:   pulumi.String("HTTP"),
				Port:       pulumi.Int(80),
				VpcId:      vpc.ID(),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new elb target group [%s]: %w", rsbService.Name, err)
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
				return fmt.Errorf("new random order integer [%s]: %w", rsbService.Name, err)
			}

			randomPriority, err := random.NewRandomInteger(ctx, fmt.Sprintf("random-priority-%s-%s", rsbService.Name, env.Name), &random.RandomIntegerArgs{
				Min: pulumi.Int(1),
				Max: pulumi.Int(4095),
			})
			if err != nil {
				return fmt.Errorf("new random priority integer [%s]: %w", rsbService.Name, err)
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
				return fmt.Errorf("new elb http listener rule [%s]: %w", rsbService.Name, err)
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
				return fmt.Errorf("new elb https listener rule [%s]: %w", rsbService.Name, err)
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
				return fmt.Errorf("new record [%s]: %w", rsbService.Name, err)
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
					return fmt.Errorf("new network load balancer [%s]: %w", rsbService.Name, err)
				}

				tgNLB, err := elasticloadbalancingv2.NewTargetGroup(ctx, fmt.Sprintf("nlb-tcp-%s-%s", rsbService.Name, env.Name), &elasticloadbalancingv2.TargetGroupArgs{
					Name:       pulumi.Sprintf("%s-nlb", shortEnvName(env.Name, rsbService.Name)),
					TargetType: pulumi.String("ip"),
					Protocol:   pulumi.String("TCP"),
					Port:       pulumi.Int(80),
					VpcId:      vpc.ID(),
				}, pulumi.Provider(awsProvider))
				if err != nil {
					return fmt.Errorf("new nlb target group [%s]: %w", rsbService.Name, err)
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
					return fmt.Errorf("new nlb http listener [%s]: %w", rsbService.Name, err)
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
					return fmt.Errorf("new nlb https listener [%s]: %w", rsbService.Name, err)
				}

				vpcLink, err := apigateway.NewVpcLink(ctx, fmt.Sprintf("vpc-link-%s-%s", rsbService.Name, env.Name), &apigateway.VpcLinkArgs{
					Name:      pulumi.Sprintf("%s-%s", env.Name, rsbService.Name),
					TargetArn: nlb.Arn,
				}, pulumi.Provider(awsProvider))
				if err != nil {
					return fmt.Errorf("new vpc link [%s]: %w", rsbService.Name, err)
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
				bastionPrivRecord.Fqdn,
				esEndpoint,
				brokerDriver,
				brokerProtocol,
				brokerVhost,
				brokerServer,
				brokerPort,
				brokerAdminPort,
				brokerAdminURL,
				brokerUsername,
				brokerPassword,
			).ApplyT(func(args []interface{}) (string, error) {
				rsbServiceName := args[4].(string)

				baseTaskDef, err := fetchFileFromGithubRepo(env.GithubOrgName, rsbServiceName, env.Name, "BaseTaskDefinition.json", env.GithubAuthToken)
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
				bastionPrivURL := args[6].(string)
				esEndpoint := args[7].(string)

				// Broker
				rawBrokerDriver := args[8].(string)
				rawBrokerProtocol := args[9].(string)
				rawBrokerVhost := args[10].(string)
				rawBrokerServer := args[11].(string)
				rawBrokerPort := args[12].(int)
				rawBrokerAdminPort := args[13].(int)
				rawBrokerAdminURL := args[14].(string)
				rawBrokerUsername := args[15].(string)
				rawBrokerPassword := args[16].(string)

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
					"REPLACEME_MESSAGE_BROKER_DRIVER": rawBrokerDriver,
					"REPLACEME_MqProtocol":            rawBrokerProtocol,
					"REPLACEME_RMQVHost":              rawBrokerVhost,
					"REPLACEME_RMQServer":             rawBrokerServer,
					"REPLACEME_RMQMasterUsername":     rawBrokerUsername,
					"REPLACEME_RMQMasterUserPassword": rawBrokerPassword,
					"REPLACEME_MqAMQPPort":            strconv.Itoa(rawBrokerPort),
					"REPLACEME_MqRabbitAdminPort":     strconv.Itoa(rawBrokerAdminPort),
					"REPLACEME_RMQAdminURL":           rawBrokerAdminURL,

					// Databases
					// "REPLACEME_DB_HOST":                          env.DBHostname,
					// "REPLACEME_DBHostname":                       env.DBHostname,
					"REPLACEME_DBMasterUsername":     env.AwsServices.RDS.Username,
					"REPLACEME_DBMasterUserPassword": dbMasterUserPassword,
					"REPLACEME_DB_DATABASE":          fmt.Sprintf("%s_%s", env.Name, svcShortName),
					"REPLACEME_LibDBTable":           fmt.Sprintf("%s_%s", env.Name, svcShortName),

					// AWS credentials
					"REPLACEME_AwsAccessKeyID":     env.AWSAccessKeyID,
					"REPLACEME_AwsSecretAccessKey": env.AWSSecretAccessKey,
					"REPLACEME_AwsRegion":          env.AWSRegion,

					// Github credentials
					"REPLACEME_GithubOrgname":    env.GithubOrgName,
					"REPLACEME_GithubOauthToken": env.GithubAuthToken,

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

				// configure Datadog logging
				// https://docs.datadoghq.com/integrations/ecs_fargate/#log-collection
				if env.ThirdPartyServices.DataDog.Enabled &&
					env.ThirdPartyServices.DataDog.ApiKey != "" &&
					env.ThirdPartyServices.DataDog.LogBaseURL != "" {
					containerDefinitions.Definitions[0]["logConfiguration"] = map[string]interface{}{
						"logDriver": "awsfirelens",
						"options": map[string]interface{}{
							"Name":           "datadog",
							"apikey":         env.ThirdPartyServices.DataDog.ApiKey,
							"Host":           env.ThirdPartyServices.DataDog.LogBaseURL,
							"dd_service":     rsbService.Name,
							"dd_source":      env.Name,
							"dd_message_key": "log",
							"TLS":            "on",
							"provider":       "ecs",
						},
					}

					containerDefinitions.Definitions = append(containerDefinitions.Definitions, map[string]interface{}{
						"essential": true,
						"firelensConfiguration": map[string]interface{}{
							"type": "fluentbit",
						},
						"image": "906394416424.dkr.ecr.eu-west-1.amazonaws.com/aws-for-fluent-bit:latest",
						"name":  "fluentbit-log-router",
					})
				} else {
					ctx.Log.Warn(fmt.Sprintf("Datadog not provisioned for %q: enable and check ApiKey and LogBaseURL.", rsbServiceName), nil)
				}

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
				return fmt.Errorf("new task definition [%s]: %w", rsbService.Name, err)
			}

			ecsService, err := ecs.NewService(ctx, fmt.Sprintf("ecs-service-%s-%s", rsbService.Name, env.Name), &ecs.ServiceArgs{
				Cluster:        cluster.ID(),
				Name:           pulumi.String(rsbService.Name),
				LaunchType:     pulumi.String("FARGATE"),
				TaskDefinition: taskDef.Arn,
				DesiredCount:   pulumi.Int(rsbService.Count),
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
				return fmt.Errorf("new ecs service [%s]: %w", rsbService.Name, err)
			}

			cb, err := codebuild.NewProject(ctx, fmt.Sprintf("cb-project-%s-%s", rsbService.Name, env.Name), &codebuild.ProjectArgs{
				Artifacts: codebuild.ProjectArtifactsArgs{
					Type: pulumi.String("NO_ARTIFACTS"),
				},
				Description: pulumi.Sprintf("Build project for %s in %s", rsbService.Name, env.Name),
				Environment: codebuild.ProjectEnvironmentArgs{
					ComputeType:              pulumi.String("BUILD_GENERAL1_SMALL"),
					Image:                    pulumi.String(env.AwsServices.Codebuild.Image),
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
							Value: bastionPrivRecord.Fqdn,
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("RSB_ENV_BASTION_URL"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.Sprintf("http://%s", bastionPubRecord.Fqdn),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("GITHUBOAUTHTOKEN"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(env.GithubAuthToken),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("DOCKER_USER"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(env.DockerHubUsername),
						},
						codebuild.ProjectEnvironmentEnvironmentVariableArgs{
							Name:  pulumi.String("DOCKER_PASSWORD"),
							Type:  pulumi.String("PLAINTEXT"),
							Value: pulumi.String(env.DockerHubPassword),
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
					Location:      pulumi.Sprintf("https://github.com/%s/%s.git", env.GithubOrgName, rsbService.Name),
					Type:          pulumi.String("GITHUB"),
				},
				SourceVersion: pulumi.String(env.Name),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new codebuild project [%s]: %w", rsbService.Name, err)
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
								Region:   pulumi.String(env.AWSRegion),
								Category: pulumi.String("Source"),
								Owner:    pulumi.String("ThirdParty"),
								Provider: pulumi.String("GitHub"),
								Version:  pulumi.String("1"),
								OutputArtifacts: pulumi.StringArray{
									pulumi.String("source"),
								},
								Configuration: pulumi.StringMap{
									"Owner":                pulumi.String(env.GithubOrgName),
									"Repo":                 pulumi.String(rsbService.Name),
									"PollForSourceChanges": pulumi.String("true"),
									"Branch":               pulumi.String(env.Name),
									"OAuthToken":           pulumi.String(env.GithubAuthToken),
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
								Region:   pulumi.String(env.AWSRegion),
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
								Region:   pulumi.String(env.AWSRegion),
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
				return fmt.Errorf("new code pipeline [%s]: %w", rsbService.Name, err)
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
			Uri: pulumi.Sprintf("https://%s/api/events", serviceRecords["rsb-service-feeder"]),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw integration events: %w", err)
		}

		var integResponses []pulumi.Resource

		for _, code := range []int{200, 201, 202, 400, 401, 403, 404, 422, 500, 503} {
			methodEventsResponse, err := apigateway.NewMethodResponse(ctx, fmt.Sprintf("api-gw-method-response-%d-events-%s", code, env.Name), &apigateway.MethodResponseArgs{
				RestApi:    apigw.ID(),
				ResourceId: resEvents.ID(),
				HttpMethod: methodEvents.HttpMethod,
				StatusCode: pulumi.Sprintf("%d", code),
			}, pulumi.DependsOn([]pulumi.Resource{integEvents}), pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new events method response [%d]: %w", code, err)
			}

			integEventsResponse, err := apigateway.NewIntegrationResponse(ctx, fmt.Sprintf("api-gw-integration-response-%d-events-%s", code, env.Name), &apigateway.IntegrationResponseArgs{
				RestApi:    apigw.ID(),
				ResourceId: resEvents.ID(),
				HttpMethod: methodEvents.HttpMethod,
				StatusCode: methodEventsResponse.StatusCode,
				SelectionPattern: pulumi.Sprintf("%d", code).ApplyT(func(c string) string {
					if c == "200" {
						// Set as default mapping
						return ""
					}
					return c
				}).(pulumi.StringOutput),
			}, pulumi.DependsOn([]pulumi.Resource{integEvents}), pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new events integration response [%d]: %w", code, err)
			}

			integResponses = append(integResponses, integEventsResponse)
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
			Uri:                   pulumi.Sprintf("https://%s/api/login", serviceRecords["rsb-service-users"]),
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw integration login: %w", err)
		}

		for _, code := range []int{200, 201, 202, 400, 401, 403, 404, 422, 500, 503} {
			methodLoginResponse, err := apigateway.NewMethodResponse(ctx, fmt.Sprintf("api-gw-method-response-%d-login-%s", code, env.Name), &apigateway.MethodResponseArgs{
				RestApi:    apigw.ID(),
				ResourceId: resLogin.ID(),
				HttpMethod: methodLogin.HttpMethod,
				StatusCode: pulumi.Sprintf("%d", code),
			}, pulumi.DependsOn([]pulumi.Resource{integLogin}), pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new login method response [%d]: %w", code, err)
			}

			integLoginResponse, err := apigateway.NewIntegrationResponse(ctx, fmt.Sprintf("api-gw-integration-response-%d-login-%s", code, env.Name), &apigateway.IntegrationResponseArgs{
				RestApi:    apigw.ID(),
				ResourceId: resLogin.ID(),
				HttpMethod: methodLogin.HttpMethod,
				StatusCode: methodLoginResponse.StatusCode,
				SelectionPattern: pulumi.Sprintf("%d", code).ApplyT(func(c string) string {
					if c == "200" {
						// Set as default mapping
						return ""
					}
					return c
				}).(pulumi.StringOutput),
			}, pulumi.DependsOn([]pulumi.Resource{integLogin}), pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new login integration response [%d]: %w", code, err)
			}

			integResponses = append(integResponses, integLoginResponse)
		}

		_, err = apigateway.NewDeployment(ctx, "api-gw-deployment-"+env.Name, &apigateway.DeploymentArgs{
			RestApi:          apigw.ID(),
			StageName:        pulumi.String("v1"),
			StageDescription: pulumi.String("v1"),
			Description:      pulumi.String("Init"),
		}, pulumi.DependsOn(integResponses), pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new rest api gw stage: %w", err)
		}

		snsTopicName := pulumi.Sprintf("rsb-alerts-%s", env.Name)
		alertTopic, err := sns.NewTopic(ctx, "topic-alarm-"+env.Name, &sns.TopicArgs{
			Name:        snsTopicName,
			DisplayName: snsTopicName,
		}, pulumi.Provider(awsProvider))
		if err != nil {
			return fmt.Errorf("new topic alarm: %w", err)
		}

		for i, recipient := range env.AwsServices.SNS.Subscriptions {
			if recipient.Endpoint == "" {
				ctx.Log.Warn(fmt.Sprintf("endpoint empty for recipient #%d", i+1), nil)
				continue
			}

			_, err = sns.NewTopicSubscription(ctx, "topic-sub-"+slugify.Slugify(recipient.Endpoint), &sns.TopicSubscriptionArgs{
				Topic:    alertTopic.ID(),
				Endpoint: pulumi.String(recipient.Endpoint),
				Protocol: pulumi.String(recipient.Protocol),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new topic alarm subscription [%s]: %w", recipient.Endpoint, err)
			}
		}

		if env.ThirdPartyServices.Telegram.BotID != "" && env.ThirdPartyServices.Telegram.ChatID != "" {
			const lambdaName = "rsb-telegram-lambda"
			lambdaRole, err := iam.NewRole(ctx, fmt.Sprintf("role-%s-%s", env.Name, lambdaName), &iam.RoleArgs{
				AssumeRolePolicy: pulumi.String(`{"Version": "2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
				Description:      pulumi.Sprintf("%s-%s", lambdaName, strings.ToLower(env.Name)),
				Path:             pulumi.String("/service-role/"),
				Name:             pulumi.Sprintf("%s-%s", lambdaName, strings.ToLower(env.Name)),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new role telegram bot [%s]: %w", lambdaName, err)
			}

			_, err = iam.NewPolicyAttachment(ctx, fmt.Sprintf("role-%s-%s", env.Name, lambdaName), &iam.PolicyAttachmentArgs{
				PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AWSLambdaFullAccess"),
				Roles: pulumi.Array{
					lambdaRole.ID(),
				},
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new policy attachment telegram bot [%s]: %w", lambdaName, err)
			}

			lambdaFunc, err := lambda.NewFunction(ctx, fmt.Sprintf("function-lambda-%s-%s", env.Name, lambdaName), &lambda.FunctionArgs{
				Code:        pulumi.NewFileArchive("static-repositories/rsb-telegram-lambda.zip"),
				Name:        pulumi.Sprintf("%s-%s", lambdaName, strings.ToLower(env.Name)),
				Handler:     pulumi.String(lambdaName),
				Role:        lambdaRole.Arn,
				Runtime:     pulumi.String("go1.x"),
				Description: pulumi.String("Send RSB Alerts from Kibana to Telegram"),
				MemorySize:  pulumi.Int(128),
				Environment: lambda.FunctionEnvironmentArgs{
					Variables: pulumi.StringMap{
						"BOT_ID":  pulumi.String(env.ThirdPartyServices.Telegram.BotID),
						"CHAT_ID": pulumi.String(env.ThirdPartyServices.Telegram.ChatID),
					},
				},
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new lambda function telegram bot [%s]: %w", lambdaName, err)
			}

			_, err = sns.NewTopicSubscription(ctx, fmt.Sprintf("topic-sub-%s-%s", env.Name, lambdaName), &sns.TopicSubscriptionArgs{
				Topic:    alertTopic.ID(),
				Endpoint: lambdaFunc.Arn,
				Protocol: pulumi.String("lambda"),
			}, pulumi.Provider(awsProvider))
			if err != nil {
				return fmt.Errorf("new topic subscription telegram bot [%s]: %w", lambdaName, err)
			}
		} else {
			ctx.Log.Warn("Telegram bot not provisioned: check BotID and ChatID.", nil)
		}

		result := pulumi.Map{
			"name":                  pulumi.String(env.Name),
			"broker_server":         brokerServer,
			"broker_admin_ui":       brokerAdminURL,
			"broker_username":       brokerUsername,
			"broker_admin_password": brokerPassword,
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
