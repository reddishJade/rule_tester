package main

import (
	"net"
	"testing"
)

func TestNormalizeProviderLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"DOMAIN,example.com", "DOMAIN,example.com"},
		{`+.example.com`, "DOMAIN-SUFFIX,example.com"},
		{".example.com", "DOMAIN-SUFFIX,example.com"},
		{"*.example.com", "DOMAIN-WILDCARD,*.example.com"},
		{"*.*.microsoft.com", "DOMAIN-WILDCARD,*.*.microsoft.com"},
		{"223.5.5.5", "IP-CIDR,223.5.5.5/32"},
		{"2001:4860:4860::8888", "IP-CIDR,2001:4860:4860::8888/128"},
		{"1.1.1.0/24", "IP-CIDR,1.1.1.0/24"},
		{"foo.example.com", "DOMAIN,foo.example.com"},
		{"foo", "DOMAIN-KEYWORD,foo"},
	}

	for _, c := range cases {
		if got := normalizeProviderLine(c.in); got != c.want {
			t.Fatalf("normalizeProviderLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMatchDomainWildcard(t *testing.T) {
	cases := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.*.example.com", "a.b.example.com", true},
		{"?.example.com", "a.example.com", true},
		{"?.example.com", "ab.example.com", false},
	}

	for _, c := range cases {
		target := &Target{Domain: c.domain}
		if got := matchDomainWildcard(c.pattern, target); got != c.want {
			t.Fatalf("matchDomainWildcard(%q,%q)=%v want %v", c.pattern, c.domain, got, c.want)
		}
	}
}

func TestRuleMatchBasics(t *testing.T) {
	targetDomain := &Target{Domain: "www.example.com"}
	targetIP := &Target{IP: net.ParseIP("223.5.5.5")}

	providers := map[string]*Provider{
		"p1": {Rules: []string{"DOMAIN-SUFFIX,example.com", "IP-CIDR,223.5.5.0/24"}},
	}

	tests := []struct {
		name   string
		rule   string
		target *Target
		want   bool
	}{
		{"domain", "DOMAIN,www.example.com,PROXY", targetDomain, true},
		{"domain-suffix", "DOMAIN-SUFFIX,example.com,PROXY", targetDomain, true},
		{"domain-keyword", "DOMAIN-KEYWORD,exam,PROXY", targetDomain, true},
		{"domain-wildcard", "DOMAIN-WILDCARD,*.example.com,PROXY", targetDomain, true},
		{"domain-regex", "DOMAIN-REGEX,^.*example\\.com$,PROXY", targetDomain, true},
		{"ip-cidr", "IP-CIDR,223.5.5.0/24,PROXY", targetIP, true},
		{"ip-cidr6-alias", "IP-CIDR6,223.5.5.0/24,PROXY", targetIP, true},
		{"rule-set-domain", "RULE-SET,p1,PROXY", targetDomain, true},
		{"rule-set-ip", "RULE-SET,p1,PROXY", targetIP, true},
	}

	for _, tc := range tests {
		ok, _ := ruleMatch(tc.rule, providers, tc.target)
		if ok != tc.want {
			t.Fatalf("%s: ruleMatch(%q)=%v want %v", tc.name, tc.rule, ok, tc.want)
		}
	}
}
