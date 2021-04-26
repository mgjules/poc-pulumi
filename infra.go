package main

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/resourcegroups"
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
				Query: pulumi.String(fmt.Sprintf("{\"ResourceTypeFilters\": [\"AWS::AllSupported\"], \"TagFilters\": [{\"Key\": \"RSB_ENV\", \"Values\": [\"%s\"]}]}", env.Name)),
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
		for groupName, subnets := range subnetGroups {
			routeTableName := "rt-" + env.Name + "-" + groupName
			rt, err := ec2.NewRouteTable(ctx, routeTableName, &ec2.RouteTableArgs{
				VpcId: vpc.ID(),
				Tags:  tags,
			})
			if err != nil {
				return fmt.Errorf("creating route table [%s]: %w", routeTableName, err)
			}

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
		_, err = ec2.NewSecurityGroup(ctx, "sg-"+env.Name, &ec2.SecurityGroupArgs{
			Name:        pulumi.String(fmt.Sprintf("%s-main", env.Name)),
			Description: pulumi.String(fmt.Sprintf("Main security group for %s", env.Name)),
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
					Protocol: pulumi.String("tcp"),
					FromPort: pulumi.Int(22),
					ToPort:   pulumi.Int(22),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				ec2.SecurityGroupIngressArgs{
					Protocol: pulumi.String("tcp"),
					FromPort: pulumi.Int(443),
					ToPort:   pulumi.Int(443),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				// Open the wireguard VPN port
				ec2.SecurityGroupIngressArgs{
					Protocol: pulumi.String("udp"),
					FromPort: pulumi.Int(51820),
					ToPort:   pulumi.Int(51820),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				// Allow connections from internal (Fargate)
				ec2.SecurityGroupIngressArgs{
					Protocol: pulumi.String("all"),
					FromPort: pulumi.Int(0),
					ToPort:   pulumi.Int(0),
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

		// TODO: implement current infra setup (bastion+ecs+fargate+mq)

		ctx.Export("vpc", vpc.Arn)
		return nil
	}
}
