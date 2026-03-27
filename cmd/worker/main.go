// dnsx-worker runs the dnsx tool as a Redis queue worker.
//
// This worker connects to Redis, pops dnsx DNS resolution jobs from a queue,
// executes them, and publishes results back to Redis for consumption
// by the Gibson framework.
//
// Usage:
//
//	dnsx-worker [flags]
//
// Flags:
//
//	-redis-url string
//	    Redis connection URL (default: REDIS_URL env or redis://localhost:6379)
//	-concurrency int
//	    Number of concurrent worker goroutines (default: 8)
//	-shutdown-timeout duration
//	    Time to wait for graceful shutdown (default: 60s)
//
// Environment Variables:
//
//	REDIS_URL       Redis connection URL (overridden by -redis-url flag)
//	LOG_LEVEL       Log level: debug, info, warn, error (default: info)
//
// The worker will:
//   - Register the dnsx tool with Redis on startup
//   - Increment the worker count for load balancing
//   - Send periodic heartbeats to maintain health status
//   - Process work items from the tool:dnsx:queue
//   - Publish results to job-specific result channels
//   - Decrement worker count and clean up on exit
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"time"

	healthhttp "github.com/zero-day-ai/sdk/health/http"
	"github.com/zero-day-ai/sdk/tool/worker"
	"github.com/zero-day-ai/sdk/types"
	"github.com/zero-day-ai/gibson-tool-dnsx"
)

func main() {
	// Parse CLI flags
	redisURL := flag.String("redis-url", os.Getenv("REDIS_URL"), "Redis URL (default: REDIS_URL env or redis://localhost:6379)")
	concurrency := flag.Int("concurrency", 0, "Number of concurrent workers (default: from component.yaml or 8)")
	shutdownTimeout := flag.Duration("shutdown-timeout", 0, "Time to wait for graceful shutdown (default: from component.yaml or 60s)")
	logLevel := flag.String("log-level", os.Getenv("LOG_LEVEL"), "Log level: debug, info, warn, error (default: info)")
	healthPort := flag.Int("health-port", 8080, "Health check HTTP port (default: 8080)")
	flag.Parse()

	// Parse log level
	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	// Create structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	// Create tool instance
	tool := dnsx.NewTool()

	// Start HTTP health server for Kubernetes probes
	healthCfg := healthhttp.DefaultConfig()
	healthCfg.Port = *healthPort
	healthServer := healthhttp.NewServer(healthCfg)

	// Register liveness check (tool binary exists)
	healthServer.RegisterLivenessCheck("tool", func(ctx context.Context) types.HealthStatus {
		return tool.Health(ctx)
	})

	// Register readiness check (same as liveness for tools)
	healthServer.RegisterReadinessCheck("tool", func(ctx context.Context) types.HealthStatus {
		return tool.Health(ctx)
	})

	if err := healthServer.Start(); err != nil {
		log.Fatalf("Failed to start health server: %v", err)
	}
	logger.Info("health server started", "port", *healthPort)

	// Ensure health server stops on exit
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		healthServer.Stop(ctx)
	}()

	// Configure worker options
	opts := worker.Options{
		RedisURL:        *redisURL,
		Concurrency:     *concurrency,
		ShutdownTimeout: *shutdownTimeout,
		Logger:          logger,
	}

	logger.Info("starting dnsx worker",
		"redis_url", opts.RedisURL,
		"concurrency", opts.Concurrency,
		"shutdown_timeout", opts.ShutdownTimeout,
	)

	// Run worker (blocks until shutdown)
	if err := worker.Run(tool, opts); err != nil {
		log.Fatalf("Worker failed: %v", err)
	}
}
