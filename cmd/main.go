package main

import (
	"log"
	"time"

	"github.com/zero-day-ai/sdk/serve"
	dnsx "github.com/zero-day-ai/gibson-tool-dnsx"
)

func main() {
	tool := dnsx.NewTool()
	if err := serve.Tool(tool,
		serve.WithPlatformFromEnv(),
		serve.WithGracefulShutdown(30*time.Second),
		serve.WithExtractor(dnsx.NewDnsxExtractor()),
	); err != nil {
		log.Fatal(err)
	}
}
