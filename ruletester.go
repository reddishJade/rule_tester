package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ClashConfig struct {
	Rules         []string                          `yaml:"rules"`
	RuleProviders map[string]map[string]interface{} `yaml:"rule-providers"`
}

type Provider struct {
	Name     string
	Type     string
	URL      string
	Behavior string
	Lines    []string
}

type Target struct {
	Domain  string
	IP      net.IP
	Port    int
	Network string
	Raw     string
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to clash config")
	targetStr := flag.String("target", "", "target to test")
	showAll := flag.Bool("show-all", false, "show trace")
	timeout := flag.Int("timeout", 6, "provider fetch timeout (sec)")
	flag.Parse()

	if err := os.MkdirAll("providers", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create cache directory: %v\n", err)
	}

	if *targetStr == "" {
		fmt.Println("missing -target")
		os.Exit(1)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		panic(err)
	}

	providers, err := loadProviders(cfg.RuleProviders, *timeout)
	if err != nil {
		panic(err)
	}

	target, err := parseTarget(*targetStr)
	if err != nil {
		panic(err)
	}

	rule, subRule, policy, trace := matchRules(cfg.Rules, providers, target)

	if *showAll {
		fmt.Println("Trace:")
		for _, t := range trace {
			fmt.Println(" -", t)
		}
	}

	fmt.Println("Matched Rule:", rule)
	if subRule != "" {
		fmt.Println("    Sub-Rule:", subRule)
	}
	fmt.Println("Policy      :", policy)
}

func loadConfig(path string) (*ClashConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ClashConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func loadProviders(rps map[string]map[string]interface{}, timeoutSec int) (map[string]*Provider, error) {
	out := map[string]*Provider{}
	for name, m := range rps {
		p := &Provider{Name: name}
		if v, ok := m["url"].(string); ok {
			p.URL = v
		}
		if v, ok := m["behavior"].(string); ok {
			p.Behavior = v
		}
		format, _ := m["format"].(string)

		if p.URL != "" {
			body, err := fetchBody(p.URL, timeoutSec)
			if err == nil {
				var lines []string
				if format == "yaml" {
					var yamlPayload struct {
						Payload []string `yaml:"payload"`
					}
					if yaml.Unmarshal(body, &yamlPayload) == nil {
						lines = yamlPayload.Payload
					}
				} else {
					lines = strings.Split(string(body), "\n")
				}
				p.Lines = parseProviderLines(lines)
			}
		}
		out[name] = p
	}
	return out, nil
}

func fetchBody(rawurl string, timeoutSec int) ([]byte, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// Handle local files directly, no caching
	if u.Scheme == "file" || u.Scheme == "" {
		path := strings.TrimPrefix(rawurl, "file://")
		return ioutil.ReadFile(path)
	}

	// Caching logic for remote URLs
	cacheDir := "providers"
	hash := sha256.Sum256([]byte(rawurl))
	cacheFile := filepath.Join(cacheDir, hex.EncodeToString(hash[:]))

	// Check for a valid cache file
	fileInfo, err := os.Stat(cacheFile)
	if err == nil { // Cache file exists
		if time.Since(fileInfo.ModTime()) < 24*time.Hour {
			return ioutil.ReadFile(cacheFile)
		}
	}

	// Fetch from network if no valid cache
	c := http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	resp, err := c.Get(rawurl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Save the downloaded content to cache
	if err := ioutil.WriteFile(cacheFile, body, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write cache file: %v\n", err)
	}

	return body, nil
}

func parseProviderLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func parseTarget(s string) (*Target, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		t := &Target{Raw: s}
		host := u.Host
		if strings.Contains(host, ":") {
			h, p, _ := net.SplitHostPort(host)
			host = h
			t.Port, _ = strconv.Atoi(p)
		}
		if ip := net.ParseIP(host); ip != nil {
			t.IP = ip
		} else {
			t.Domain = strings.ToLower(host)
		}
		if t.Port == 0 {
			if u.Scheme == "https" {
				t.Port = 443
			} else if u.Scheme == "http" {
				t.Port = 80
			}
		}
		return t, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return &Target{IP: ip, Raw: s}, nil
	}
	return &Target{Domain: strings.ToLower(s), Raw: s}, nil
}

func matchRules(rules []string, providers map[string]*Provider, t *Target) (string, string, string, []string) {
	var trace []string
	for _, r := range rules {
		trace = append(trace, r)
		if ok, subMatch := ruleMatch(r, providers, t); ok {
			policy := ""
			parts := strings.Split(r, ",")
			if len(parts) >= 3 {
				policy = strings.TrimSpace(parts[2])
			}

			mainRulePart := r
			if len(parts) >= 2 {
				mainRulePart = strings.Join(parts[0:2], ",")
			}

			if mainRulePart == subMatch {
				subMatch = ""
			}

			return r, subMatch, policy, trace
		}
	}
	return "", "", "", trace
}

func ruleMatch(rule string, providers map[string]*Provider, t *Target) (bool, string) {
	parts := strings.Split(rule, ",")
	typ := strings.ToUpper(strings.TrimSpace(parts[0]))

	switch typ {

	case "DOMAIN":
		if len(parts) > 1 && t.Domain != "" && t.Domain == parts[1] {
			return true, strings.Join(parts[0:2], ",")
		}
		return false, ""

	case "DOMAIN-SUFFIX":
		if len(parts) > 1 && t.Domain != "" &&
			(t.Domain == parts[1] || strings.HasSuffix(t.Domain, "."+parts[1])) {
			return true, strings.Join(parts[0:2], ",")
		}
		return false, ""

	case "DOMAIN-KEYWORD":
		if len(parts) > 1 && t.Domain != "" && strings.Contains(t.Domain, parts[1]) {
			return true, strings.Join(parts[0:2], ",")
		}
		return false, ""

	case "IP-CIDR":
		if len(parts) > 1 && t.IP != nil {
			_, cidr, err := net.ParseCIDR(parts[1])
			if err == nil && cidr.Contains(t.IP) {
				return true, strings.Join(parts[0:2], ",")
			}
		}
		return false, ""

	case "RULE-SET":
		if len(parts) > 2 {
			if p, ok := providers[parts[1]]; ok {
				for _, ln := range p.Lines {
					normalizedRule := normalizeProviderLine(ln)
					if ok, matchedRule := ruleMatch(normalizedRule+","+parts[2], providers, t); ok {
						return true, matchedRule
					}
				}
			}
		}
		return false, ""

	case "MATCH":
		return true, rule
	}
	return false, ""
}

func normalizeProviderLine(s string) string {
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "+.") {
		return "DOMAIN-SUFFIX," + s[2:]
	}

	// Check if the line is already a full rule
	parts := strings.SplitN(s, ",", 2)
	if len(parts) == 2 {
		typ := strings.ToUpper(parts[0])
		switch typ {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "RULE-SET", "MATCH":
			return s // It's already a full rule, return as-is
		}
	}

	// Fix for plain IPs being treated as domains
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return "IP-CIDR," + s + "/32"
		}
		return "IP-CIDR," + s + "/128"
	}

	// New logic: If the string looks like a standard domain name (contains a dot,
	// doesn't start with '+' or '.', and doesn't contain '/') then treat it as DOMAIN.
	if !strings.HasPrefix(s, "+.") && !strings.HasPrefix(s, ".") && strings.Contains(s, ".") && !strings.Contains(s, "/") {
		return "DOMAIN," + s
	}

	if strings.HasPrefix(s, ".") {
		return "DOMAIN-SUFFIX," + s[1:]
	}
	if strings.Contains(s, "/") {
		return "IP-CIDR," + s
	}
	// Fallback to DOMAIN-KEYWORD if none of the above matches
	return "DOMAIN-KEYWORD," + s
}
