package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Scope holds the authoritative in-scope definition for a campaign.
type Scope struct {
	networks []*net.IPNet
	domains  []string
	excluded []*net.IPNet
}

func NewScope(networks, domains, excluded []string) (*Scope, error) {
	s := &Scope{}

	for _, n := range networks {
		_, ipnet, err := net.ParseCIDR(n)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q: %w", n, err)
		}
		s.networks = append(s.networks, ipnet)
	}

	for _, d := range domains {
		s.domains = append(s.domains, strings.ToLower(d))
	}

	for _, n := range excluded {
		_, ipnet, err := net.ParseCIDR(n)
		if err != nil {
			return nil, fmt.Errorf("invalid excluded network %q: %w", n, err)
		}
		s.excluded = append(s.excluded, ipnet)
	}

	return s, nil
}

// Check returns nil if target is in scope, or an error describing the violation.
// Handles IPs, CIDRs, hostnames, host:port pairs, and full URLs.
func (s *Scope) Check(target string) error {
	host := extractHost(target)

	ip := net.ParseIP(host)
	if ip != nil {
		return s.checkIP(ip, target)
	}

	// CIDR range — check the network address itself
	if strings.Contains(host, "/") {
		_, ipnet, err := net.ParseCIDR(host)
		if err == nil {
			return s.checkIP(ipnet.IP, target)
		}
	}

	return s.checkDomain(host, target)
}

func (s *Scope) checkIP(ip net.IP, original string) error {
	for _, excl := range s.excluded {
		if excl.Contains(ip) {
			return fmt.Errorf("%s is in excluded range %s", original, excl)
		}
	}
	for _, network := range s.networks {
		if network.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("%s not in any allowed network", original)
}

func (s *Scope) checkDomain(host, original string) error {
	h := strings.ToLower(host)
	for _, domain := range s.domains {
		if h == domain || strings.HasSuffix(h, "."+domain) {
			return nil
		}
	}
	return fmt.Errorf("%s not in allowed domains", original)
}

// extractHost pulls the hostname/IP from a target that may be an IP,
// host:port pair, or full URL.
func extractHost(target string) string {
	// Full URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if u, err := url.Parse(target); err == nil {
			return u.Hostname()
		}
	}
	// host:port
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}
