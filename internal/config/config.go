package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Bind           string
	APIKey         string
	HardenKey      string
	RateLimit      int
	LogLevel       string
	WhitelistPorts []int
}

func Load() (*Config, error) {
	cfg := &Config{
		Bind:      getEnv("HARDENED_API_BIND", "127.0.0.1:8080"),
		APIKey:    os.Getenv("HARDENED_API_KEY"),
		HardenKey: os.Getenv("HARDENED_API_HARDEN_KEY"),
		RateLimit: getEnvInt("HARDENED_API_RATE_LIMIT", 60),
		LogLevel:  getEnv("HARDENED_API_LOG_LEVEL", "info"),
	}

	if os.Getenv("HARDENED_API_USER") == "" {
		return nil, fmt.Errorf("HARDENED_API_USER is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("HARDENED_API_KEY is required")
	}
	if cfg.HardenKey == "" {
		cfg.HardenKey = cfg.APIKey
	}

	raw := getEnv("HARDENED_API_WHITELIST_PORTS", "22,80,443")
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port in HARDENED_API_WHITELIST_PORTS: %s", part)
		}
		cfg.WhitelistPorts = append(cfg.WhitelistPorts, n)
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
