package dnsx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
	"github.com/zero-day-ai/gibson-tool-dnsx/gen"
	"google.golang.org/protobuf/proto"
)

const (
	ToolName    = "dnsx"
	ToolVersion = "1.0.0"
	ToolDescription = `Fast and multi-purpose DNS toolkit for DNS resolution and record enumeration.

DNS RECORD TYPES:
  -a               Query A records (IPv4 addresses)
  -aaaa            Query AAAA records (IPv6 addresses)
  -cname           Query CNAME records (canonical names)
  -mx              Query MX records (mail exchange)
  -ns              Query NS records (name servers)
  -txt             Query TXT records
  -ptr             Query PTR records (reverse DNS)
  -soa             Query SOA records
  -any             Query ANY records

PERFORMANCE:
  -t N             Number of concurrent threads (default: 100)
  -rate-limit N    Maximum DNS requests per second
  -retry N         Number of retries for failed queries (default: 2)
  -timeout N       DNS query timeout in seconds (default: 5)

OUTPUT:
  -json            Output in JSON format (automatically enabled)
  -resp            Display DNS response
  -resp-only       Display only DNS response

RESOLVER OPTIONS:
  -r RESOLVER      Use custom DNS resolver(s)
  -rl FILE         Read custom resolvers from file

COMMON EXAMPLES:
  A records: hosts=["example.com"], resolve_a=true
  CNAME records: hosts=["www.example.com"], resolve_cname=true
  MX records: hosts=["example.com"], resolve_mx=true
  Multiple records: hosts=["example.com"], resolve_a=true, resolve_cname=true
  Fast resolution: hosts=["example.com"], resolve_a=true, threads=200`
	BinaryName = "dnsx"
	// Large host list threshold - if exceeded, write to temp file
	LargeHostListThreshold = 1000
)

// ToolImpl implements the dnsx tool
type ToolImpl struct{}

// NewTool creates a new dnsx tool instance
func NewTool() tool.Tool {
	return &ToolImpl{}
}

// Name returns the tool name
func (t *ToolImpl) Name() string {
	return ToolName
}

// Version returns the tool version
func (t *ToolImpl) Version() string {
	return ToolVersion
}

// Description returns the tool description
func (t *ToolImpl) Description() string {
	return ToolDescription
}

// Tags returns the tool tags
func (t *ToolImpl) Tags() []string {
	return []string{
		"discovery",
		"dns",
		"enumeration",
		"T1590", // Gather Victim Network Information
	}
}

// InputMessageType returns the proto message type for input
func (t *ToolImpl) InputMessageType() string {
	return "gibson.tools.dnsx.DnsxRequest"
}

// OutputMessageType returns the proto message type for output
func (t *ToolImpl) OutputMessageType() string {
	return "gibson.tools.dnsx.DnsxResponse"
}

// InputProto returns a prototype instance of the input message.
// Implements the serve.SchemaProvider interface for reliable schema extraction.
func (t *ToolImpl) InputProto() proto.Message {
	return &gen.DnsxRequest{}
}

// OutputProto returns a prototype instance of the output message.
// Implements the serve.SchemaProvider interface for reliable schema extraction.
func (t *ToolImpl) OutputProto() proto.Message {
	return &gen.DnsxResponse{}
}

// ExecuteProto runs the dnsx tool with proto message input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert input to DnsxRequest
	req, ok := input.(*gen.DnsxRequest)
	if !ok {
		return nil, fmt.Errorf("invalid input type: expected *gen.DnsxRequest, got %T", input)
	}

	// Validate required fields
	if len(req.Hosts) == 0 {
		return nil, fmt.Errorf("at least one host is required")
	}

	// Validate at least one record type is requested
	if !req.ResolveA && !req.ResolveCname && !req.ResolveMx {
		return nil, fmt.Errorf("at least one DNS record type must be requested (resolve_a, resolve_cname, or resolve_mx)")
	}

	// Build dnsx command arguments
	args := buildArgs(req)

	// Handle large host lists efficiently - write to temp file if needed
	var tempFile string
	var inputData []byte
	var cleanupFunc func()

	if len(req.Hosts) > LargeHostListThreshold {
		// Create temp file for large host lists
		tmpFile, err := os.CreateTemp("", "dnsx-hosts-*.txt")
		if err != nil {
			return nil, toolerr.New(ToolName, "prepare", toolerr.ErrCodeExecutionFailed,
				fmt.Sprintf("failed to create temp file: %v", err)).
				WithClass(toolerr.ErrorClassInfrastructure)
		}
		tempFile = tmpFile.Name()

		// Write hosts to temp file
		for _, host := range req.Hosts {
			if _, err := tmpFile.WriteString(host + "\n"); err != nil {
				tmpFile.Close()
				os.Remove(tempFile)
				return nil, toolerr.New(ToolName, "prepare", toolerr.ErrCodeExecutionFailed,
					fmt.Sprintf("failed to write to temp file: %v", err)).
					WithClass(toolerr.ErrorClassInfrastructure)
			}
		}
		tmpFile.Close()

		// Add -list flag to read from file
		args = append(args, "-list", tempFile)

		// Set cleanup function
		cleanupFunc = func() {
			os.Remove(tempFile)
		}
	} else {
		// For small lists, pass via stdin
		inputData = []byte(strings.Join(req.Hosts, "\n"))
	}

	// Ensure cleanup happens
	if cleanupFunc != nil {
		defer cleanupFunc()
	}

	// Set timeout from request or use default
	timeout := 5 * time.Minute
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}

	// Execute dnsx command
	result, err := exec.Run(ctx, exec.Config{
		Command:   BinaryName,
		Args:      args,
		StdinData: inputData,
		Timeout:   timeout,
	})

	if err != nil {
		// Classify execution errors based on underlying cause
		errClass := classifyExecutionError(err)
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).
			WithCause(err).
			WithClass(errClass)
	}

	// Parse dnsx JSON output to proto types
	results, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).
			WithCause(err).
			WithClass(toolerr.ErrorClassSemantic)
	}

	// Convert results to DnsxResponse
	scanDuration := time.Since(startTime).Seconds()
	response := convertToProtoResponse(results, scanDuration)

	return response, nil
}

// Health checks if the dnsx binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// DnsxJSONResult represents the JSON output from dnsx
type DnsxJSONResult struct {
	Host      string   `json:"host"`
	A         []string `json:"a"`
	AAAA      []string `json:"aaaa"`
	CNAME     []string `json:"cname"`
	MX        []string `json:"mx"`
	NS        []string `json:"ns"`
	TXT       []string `json:"txt"`
	PTR       []string `json:"ptr"`
	SOA       []string `json:"soa"`
	Timestamp string   `json:"timestamp"`
	Status    string   `json:"status"`
}

// parseOutput parses the JSON output from dnsx and returns proto DnsResults.
func parseOutput(data []byte) ([]*gen.DnsResult, error) {
	var results []*gen.DnsResult

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var jsonResult DnsxJSONResult
		if err := json.Unmarshal(line, &jsonResult); err != nil {
			// Skip malformed lines
			continue
		}

		results = append(results, convertJSONToProtoResult(&jsonResult))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan dnsx output: %w", err)
	}

	return results, nil
}

// convertJSONToProtoResult converts dnsx JSON result to proto DnsResult
func convertJSONToProtoResult(jsonResult *DnsxJSONResult) *gen.DnsResult {
	protoResult := &gen.DnsResult{
		Host:     jsonResult.Host,
		ARecords: jsonResult.A,
		Status:   determineStatus(jsonResult),
	}

	// Add CNAME records if present
	if len(jsonResult.CNAME) > 0 {
		protoResult.CnameRecords = jsonResult.CNAME
	}

	return protoResult
}

// determineStatus determines the resolution status from the JSON result
func determineStatus(jsonResult *DnsxJSONResult) string {
	// If status is explicitly provided, use it
	if jsonResult.Status != "" {
		return jsonResult.Status
	}

	// Otherwise determine based on presence of records
	if len(jsonResult.A) > 0 || len(jsonResult.AAAA) > 0 ||
	   len(jsonResult.CNAME) > 0 || len(jsonResult.MX) > 0 {
		return "success"
	}

	return "no_records"
}

// convertToProtoResponse wraps DNS results in a DnsxResponse.
// The Discovery field (proto field 100) is populated by the SDK serve layer
// via the DnsxExtractor after execution.
func convertToProtoResponse(results []*gen.DnsResult, scanDuration float64) *gen.DnsxResponse {
	return &gen.DnsxResponse{
		Results: results,
	}
}

// classifyExecutionError determines the error class based on the underlying error
func classifyExecutionError(err error) toolerr.ErrorClass {
	if err == nil {
		return toolerr.ErrorClassTransient
	}

	errMsg := err.Error()

	// Check for binary not found errors
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "executable file not found") {
		return toolerr.ErrorClassInfrastructure
	}

	// Check for timeout errors
	if strings.Contains(errMsg, "timed out") || strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "deadline exceeded") {
		return toolerr.ErrorClassTransient
	}

	// Check for permission errors
	if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "access denied") {
		return toolerr.ErrorClassInfrastructure
	}

	// Check for network errors
	if strings.Contains(errMsg, "network") || strings.Contains(errMsg, "connection") ||
		strings.Contains(errMsg, "host unreachable") || strings.Contains(errMsg, "no route to host") {
		return toolerr.ErrorClassTransient
	}

	// Check for DNS-specific errors
	if strings.Contains(errMsg, "no such host") || strings.Contains(errMsg, "dns") {
		return toolerr.ErrorClassTransient
	}

	// Check for cancellation
	if strings.Contains(errMsg, "cancelled") || strings.Contains(errMsg, "canceled") {
		return toolerr.ErrorClassTransient
	}

	// Default to transient for unknown execution errors
	return toolerr.ErrorClassTransient
}

// buildArgs builds the command line arguments for dnsx
func buildArgs(req *gen.DnsxRequest) []string {
	// Always start with -json for JSON output
	args := []string{"-json"}

	// DNS record type flags
	if req.ResolveA {
		args = append(args, "-a")
	}

	if req.ResolveCname {
		args = append(args, "-cname")
	}

	if req.ResolveMx {
		args = append(args, "-mx")
	}

	// Response display - show full DNS response
	args = append(args, "-resp")

	return args
}
