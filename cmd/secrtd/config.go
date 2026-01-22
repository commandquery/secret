package main

import (
	"strings"

	"github.com/kelseyhightower/envconfig"
)

var Config struct {
	DatabaseDSN      string `split_words:"true"`
	Store            string `split_words:"true"`
	SignatureSkew    int64  `split_words:"true" default:"5"`
	ChallengeSize    int    `split_words:"true" default:"20"` // Incrementing by 1 *doubles* the complexity
	PathPrefix       string `split_words:"true" default:"/"`
	ServerConfigPath string `split_words:"true" default:"./server.json"`
	AutoEnrol        bool   `split_words:"true" default:"false"`
}

func initConfig() error {
	if err := envconfig.Process("secrt", &Config); err != nil {
		return err
	}

	if !strings.HasSuffix(Config.PathPrefix, "/") {
		Config.PathPrefix += "/"
	}

	return nil
}
