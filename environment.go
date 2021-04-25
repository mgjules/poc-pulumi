package main

import (
	"errors"
	"regexp"
)

type environment struct {
	Name string `json:"name" binding:"required"`
}

func (e environment) validate() error {
	if ok, err := regexp.MatchString(`^[a-z]{1,8}$`, e.Name); !ok || err != nil {
		return errors.New("environment name must be 1-8 all lower case characters")
	}

	return nil
}
