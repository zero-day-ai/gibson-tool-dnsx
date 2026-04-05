package dnsx

import (
	"context"
	"fmt"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/extraction"
	"github.com/zero-day-ai/gibson-tool-dnsx/gen"
	"google.golang.org/protobuf/proto"
)

// DnsxExtractor extracts entities from dnsx DNS resolution results.
// It converts DnsxResponse proto messages into a DiscoveryResult containing:
//   - Domain entities (one per queried hostname)
//   - Host entities (one per resolved A record IP, deduplicated across hostnames)
type DnsxExtractor struct{}

// NewDnsxExtractor creates a new DnsxExtractor instance.
func NewDnsxExtractor() *DnsxExtractor {
	return &DnsxExtractor{}
}

func (e *DnsxExtractor) ToolName() string                 { return "dnsx" }
func (e *DnsxExtractor) CanExtract(msg proto.Message) bool { _, ok := msg.(*gen.DnsxResponse); return ok }

// Extract converts a DnsxResponse into a DiscoveryResult.
// Each queried hostname becomes a Domain entity. Each resolved A record IP
// becomes a Host entity with the first hostname linked. IPs are deduplicated
// across all DNS results so a shared CDN IP only produces one Host node.
func (e *DnsxExtractor) Extract(ctx context.Context, msg proto.Message) (*graphragpb.DiscoveryResult, error) {
	resp, ok := msg.(*gen.DnsxResponse)
	if !ok {
		return nil, fmt.Errorf("expected *gen.DnsxResponse, got %T", msg)
	}

	if len(resp.Results) == 0 {
		return &graphragpb.DiscoveryResult{}, nil
	}

	discovery := &graphragpb.DiscoveryResult{}

	// Track seen IPs to deduplicate Host nodes across multiple DNS results.
	seenIPs := make(map[string]bool)

	for _, result := range resp.Results {
		if result == nil || result.Host == "" {
			continue
		}

		// Each resolved hostname becomes a Domain entity.
		domainID := extraction.DomainID(result.Host)
		domain := &graphragpb.Domain{
			Id:   &domainID,
			Name: result.Host,
		}
		discovery.Domains = append(discovery.Domains, domain)

		// Each A record resolves to a Host entity.
		for _, ip := range result.ARecords {
			if ip == "" || seenIPs[ip] {
				continue
			}
			seenIPs[ip] = true

			hostID := extraction.HostID(ip)
			host := &graphragpb.Host{
				Id:       &hostID,
				Ip:       ip,
				Hostname: extraction.StringPtr(result.Host),
			}
			discovery.Hosts = append(discovery.Hosts, host)
		}
	}

	return discovery, nil
}
