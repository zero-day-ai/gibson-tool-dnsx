# DNSX Discovery Tool

DNS resolution and record enumeration tool for domain infrastructure mapping.

## Entity Extraction

The dnsx tool extracts the following entities to the GraphRAG knowledge graph:

### Entities

| Entity Type | Description | Key Fields |
|-------------|-------------|------------|
| **Domain** | Queried domains | `name` |
| **Subdomain** | DNS-resolved subdomains | `name`, `domain_id` |
| **Host** | Resolved IP addresses | `ip`, `hostname` |

### DNS Record Types

The tool queries and extracts various DNS record types:
- `A` - IPv4 addresses
- `AAAA` - IPv6 addresses
- `CNAME` - Canonical names
- `MX` - Mail exchangers
- `NS` - Name servers
- `TXT` - Text records
- `SOA` - Start of authority

### Relationships

| Relationship Type | From | To | Description |
|-------------------|------|------|-------------|
| `HAS_SUBDOMAIN` | Domain | Subdomain | Domain has a subdomain |
| `RESOLVES_TO` | Subdomain | Host | Subdomain resolves to IP |

### Entity ID Generation

Entity IDs are deterministically generated using SHA1-based UUIDs for idempotency:

- **Domain**: `uuid5(OID, "domain:{domain_name}")`
- **Subdomain**: `uuid5(OID, "subdomain:{subdomain_name}")`
- **Host**: `uuid5(OID, "host:{ip}")`

## Example Graph Structure

```
[Domain: example.com]
    └── HAS_SUBDOMAIN → [Subdomain: api.example.com]
                              └── RESOLVES_TO → [Host: 93.184.216.34]

[Domain: example.com]
    └── HAS_SUBDOMAIN → [Subdomain: www.example.com]
                              └── RESOLVES_TO → [Host: 93.184.216.34]
```

## Provenance

All relationships include provenance properties:

- `discovered_by`: `"dnsx"`
- `discovered_at`: Unix timestamp (milliseconds)
- `mission_run_id`: Mission context identifier

## Metadata

Extraction metadata includes:

- `domain_count`: Number of domains queried
- `subdomain_count`: Number of subdomains resolved
- `host_count`: Number of unique IP addresses
- `record_types`: DNS record types queried
- `resolver_count`: Number of DNS resolvers used
- `scan_duration`: Total resolution duration in seconds
