package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Server struct {
	PrivateKey string `yaml:"private_key"`
	Listen     string `yaml:"listen"`
	PSK        string `yaml:"psk"`
	IPPool     string `yaml:"ip_pool"`
	Metrics    string `yaml:"metrics_addr"`
}

type Client struct {
	Server     string   `yaml:"server"`
	PSK        string   `yaml:"psk"`
	Interface  string   `yaml:"interface"`
	Routes     []string `yaml:"routes"`
	PrivateKey string   `yaml:"private_key"`
	Metrics    string   `yaml:"metrics_addr"`
}

func LoadServer(path string) (*Server, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Server
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func LoadClient(path string) (*Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Client
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
