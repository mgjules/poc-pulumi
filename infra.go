package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func infra(stackName string) pulumi.RunFunc {
	return func(ctx *pulumi.Context) error {
		// TODO: replace with current infra setup (vpc+ec2+ecs+igw+dynamodb+mq)

		ctx.Export("TODO", pulumi.String("not implemented yet"))
		return nil
	}
}
