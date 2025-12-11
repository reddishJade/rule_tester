package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type ClashConfig struct {
	Rules         []string                          `yaml:"rules"`
	RuleProviders map[string]map[string]interface{} `yaml:"rule-providers"`
}

type Provider struct {
	Name  string
	URL   string
	Rules []string
}

type Target struct {
	Domain  string
	IP      net.IP
	Port    int
	Network string
	Raw     string
}

type MatchResult struct {
	Matched bool
	Rule    string
	SubRule string
	Policy  string
	Trace   []string
}

var cidrCache sync.Map
var regexCache sync.Map

type ruleMatcher func(value string, t *Target) bool

var matchers = map[string]ruleMatcher{
	"DOMAIN":          matchDomain,
	"DOMAIN-SUFFIX":   matchDomainSuffix,
	"DOMAIN-KEYWORD":  matchDomainKeyword,
	"DOMAIN-WILDCARD": matchDomainWildcard,
	"DOMAIN-REGEX":    matchDomainRegex,
	"IP-CIDR":         matchIPCIDR,
	"IP-CIDR6":        matchIPCIDR, // IP-CIDR6 是 IP-CIDR 的别名
	"MATCH":           func(string, *Target) bool { return true },
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
		fmt.Fprintf(os.Stderr, "Warning: some providers failed to load: %v\n", err)
	}

	target, err := parseTarget(*targetStr)
	if err != nil {
		panic(err)
	}

	result := matchRules(cfg.Rules, providers, target)

	if *showAll {
		fmt.Println("Trace:")
		for _, t := range result.Trace {
			fmt.Println(" -", t)
		}
	}

	fmt.Println("Matched Rule:", result.Rule)
	if result.SubRule != "" {
		fmt.Println("    Sub-Rule:", result.SubRule)
	}
	fmt.Println("Policy      :", result.Policy)
}

func loadConfig(path string) (*ClashConfig, error) {
	b, err := os.ReadFile(path)
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
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	var firstErr error

	for name, m := range rps {
		wg.Add(1)
		go func(name string, m map[string]interface{}) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			provider, err := buildProvider(name, m, timeoutSec)
			mu.Lock()
			out[name] = provider
			if err != nil && firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}(name, m)
	}

	wg.Wait()
	return out, firstErr
}

func buildProvider(name string, m map[string]interface{}, timeoutSec int) (*Provider, error) {
	p := &Provider{Name: name}
	if v, ok := m["url"].(string); ok {
		p.URL = v
	}
	if p.URL == "" {
		return p, nil
	}

	body, err := fetchBody(p.URL, timeoutSec)
	if err != nil {
		return p, fmt.Errorf("provider %s: %w", name, err)
	}

	p.Rules = parseProviderBody(body, m["format"] == "yaml")
	return p, nil
}

func fetchBody(rawurl string, timeoutSec int) ([]byte, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// 本地文件直接读取
	if u.Scheme == "file" || u.Scheme == "" {
		return os.ReadFile(strings.TrimPrefix(rawurl, "file://"))
	}

	return fetchRemoteWithCache(rawurl, timeoutSec)
}

func fetchRemoteWithCache(rawurl string, timeoutSec int) ([]byte, error) {
	cacheFile := cacheFilePath(rawurl)

	// 缓存有效则返回
	if info, err := os.Stat(cacheFile); err == nil {
		if time.Since(info.ModTime()) < 24*time.Hour {
			return os.ReadFile(cacheFile)
		}
	}

	// 从网络获取
	body, err := fetchHTTP(rawurl, timeoutSec)
	if err != nil {
		return nil, err
	}

	// 写入缓存，失败不影响返回
	if err := os.WriteFile(cacheFile, body, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cache write failed: %v\n", err)
	}
	return body, nil
}

func cacheFilePath(rawurl string) string {
	hash := sha256.Sum256([]byte(rawurl))
	return filepath.Join("providers", hex.EncodeToString(hash[:]))
}

func fetchHTTP(rawurl string, timeoutSec int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func parseProviderBody(body []byte, isYAML bool) []string {
	var lines []string
	if isYAML {
		var payload struct {
			Payload []string `yaml:"payload"`
		}
		if yaml.Unmarshal(body, &payload) == nil {
			lines = payload.Payload
		}
	}
	if len(lines) == 0 {
		lines = strings.Split(string(body), "\n")
	}

	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		out = append(out, normalizeProviderLine(l))
	}
	return out
}

func parseTarget(s string) (*Target, error) {
	s = strings.TrimSpace(s)

	// 纯 IP 地址
	if ip := net.ParseIP(s); ip != nil {
		return &Target{IP: ip, Raw: s}, nil
	}

	// URL 格式
	if strings.Contains(s, "://") {
		return parseURLTarget(s)
	}

	// 纯域名
	return &Target{Domain: strings.ToLower(s), Raw: s}, nil
}

func parseURLTarget(s string) (*Target, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	t := &Target{Raw: s}
	host, portStr := u.Host, ""

	if h, p, err := net.SplitHostPort(u.Host); err == nil {
		host, portStr = h, p
	}

	if ip := net.ParseIP(host); ip != nil {
		t.IP = ip
	} else {
		t.Domain = strings.ToLower(host)
	}

	if portStr != "" {
		t.Port, _ = strconv.Atoi(portStr)
	} else {
		t.Port = defaultPort(u.Scheme)
	}

	return t, nil
}

func defaultPort(scheme string) int {
	switch scheme {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

func matchDomain(value string, t *Target) bool {
	return t.Domain != "" && t.Domain == value
}

func matchDomainSuffix(value string, t *Target) bool {
	return t.Domain != "" && (t.Domain == value || strings.HasSuffix(t.Domain, "."+value))
}

func matchDomainKeyword(value string, t *Target) bool {
	return t.Domain != "" && strings.Contains(t.Domain, value)
}

func matchDomainWildcard(value string, t *Target) bool {
	if t.Domain == "" {
		return false
	}
	re := wildcardToRegex(value)
	return re != nil && re.MatchString(t.Domain)
}

func matchDomainRegex(value string, t *Target) bool {
	if t.Domain == "" {
		return false
	}
	re := parseRegexWithCache(value)
	return re != nil && re.MatchString(t.Domain)
}

func matchIPCIDR(value string, t *Target) bool {
	if t.IP == nil {
		return false
	}
	cidr := parseCIDRWithCache(value)
	return cidr != nil && cidr.Contains(t.IP)
}

func matchRules(rules []string, providers map[string]*Provider, t *Target) MatchResult {
	result := MatchResult{Trace: make([]string, 0, len(rules))}

	for _, rule := range rules {
		result.Trace = append(result.Trace, rule)
		if ok, subMatch := ruleMatch(rule, providers, t); ok {
			parts := strings.Split(rule, ",")
			if len(parts) >= 3 {
				result.Policy = strings.TrimSpace(parts[2])
			}
			result.Rule = rule
			result.Matched = true
			// SubRule 只在 RULE-SET 匹配时有意义
			if strings.HasPrefix(rule, "RULE-SET,") {
				result.SubRule = subMatch
			}
			return result
		}
	}
	return result
}

func ruleMatch(rule string, providers map[string]*Provider, t *Target) (bool, string) {
	parts := strings.Split(rule, ",")
	if len(parts) < 1 {
		return false, ""
	}

	typ := strings.ToUpper(strings.TrimSpace(parts[0]))

	// RULE-SET 需要特殊处理（递归）
	if typ == "RULE-SET" {
		return matchRuleSet(parts, providers, t)
	}

	matcher, ok := matchers[typ]
	if !ok {
		return false, ""
	}

	value := ""
	if len(parts) > 1 {
		value = parts[1]
	}

	if matcher(value, t) {
		return true, typ + "," + value
	}
	return false, ""
}

func matchRuleSet(parts []string, providers map[string]*Provider, t *Target) (bool, string) {
	if len(parts) < 3 {
		return false, ""
	}
	p, ok := providers[parts[1]]
	if !ok || len(p.Rules) == 0 {
		return false, ""
	}

	policy := parts[2]
	for _, rule := range p.Rules {
		if ok, matched := ruleMatch(rule+","+policy, providers, t); ok {
			return true, matched
		}
	}
	return false, ""
}

func parseCIDRWithCache(s string) *net.IPNet {
	if v, ok := cidrCache.Load(s); ok {
		return v.(*net.IPNet)
	}
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		return nil
	}
	cidrCache.Store(s, cidr)
	return cidr
}

func parseRegexWithCache(expr string) *regexp.Regexp {
	if v, ok := regexCache.Load(expr); ok {
		return v.(*regexp.Regexp)
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil
	}
	regexCache.Store(expr, re)
	return re
}

// wildcardToRegex: '*' 匹配单个域名层级，'?' 匹配单个字符
func wildcardToRegex(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString("[^.]+") // 匹配一个域名层级
		case '?':
			b.WriteString("[^.]") // 匹配单个字符(非点)
		case '.':
			b.WriteString(`\.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteString("$")
	return parseRegexWithCache(b.String())
}

func normalizeProviderLine(s string) string {
	if s == "" {
		return ""
	}

	// 已经是完整格式
	if strings.ContainsRune(s, ',') {
		return s
	}

	// 处理前缀: +. 和 . 都是 DOMAIN-SUFFIX
	if len(s) >= 2 && s[0] == '+' && s[1] == '.' {
		return "DOMAIN-SUFFIX," + s[2:]
	}
	if len(s) >= 1 && s[0] == '.' {
		return "DOMAIN-SUFFIX," + s[1:]
	}

	// 通配符模式
	if strings.ContainsAny(s, "*?") {
		return "DOMAIN-WILDCARD," + s
	}

	// IP 地址处理: CIDR 或纯 IP
	if strings.ContainsRune(s, '/') {
		return "IP-CIDR," + s
	}
	if ip := net.ParseIP(s); ip != nil {
		cidr := "/32"
		if ip.To4() == nil {
			cidr = "/128"
		}
		return "IP-CIDR," + s + cidr
	}

	// 域名或关键词: 包含点视为完整域名,否则为关键词
	if strings.ContainsRune(s, '.') {
		return "DOMAIN," + s
	}
	return "DOMAIN-KEYWORD," + s
}
