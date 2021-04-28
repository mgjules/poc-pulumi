package main

import (
	"fmt"
	"strings"
)

const _rsbServicePrefix = "rsb-service-"

func shortName(name string) string {
	return strings.Replace(name, _rsbServicePrefix, "", 1)
}

func shortEnvName(env, name string) string {
	return fmt.Sprintf("%s-%s", env, shortName(name))
}
