// Package tracing provides OpenTelemetry tracing configuration and utilities.
package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func TestConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{
			name:     "enabled when endpoint is set",
			endpoint: "localhost:4317",
			want:     true,
		},
		{
			name:     "disabled when endpoint is empty",
			endpoint: "",
			want:     false,
		},
		{
			name:     "enabled with http endpoint",
			endpoint: "http://localhost:4318/v1/traces",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Endpoint: tt.endpoint}
			if got := cfg.IsEnabled(); got != tt.want {
				t.Errorf("Config.IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Endpoint != "" {
		t.Errorf("DefaultConfig().Endpoint = %q, want empty string", cfg.Endpoint)
	}
	if cfg.Protocol != "grpc" {
		t.Errorf("DefaultConfig().Protocol = %q, want %q", cfg.Protocol, "grpc")
	}
	if cfg.ServiceName != "aqua-scan-gate-controller" {
		t.Errorf("DefaultConfig().ServiceName = %q, want %q", cfg.ServiceName, "aqua-scan-gate-controller")
	}
	if cfg.ServiceVersion != "0.1.0" {
		t.Errorf("DefaultConfig().ServiceVersion = %q, want %q", cfg.ServiceVersion, "0.1.0")
	}
	if cfg.SampleRatio != 1.0 {
		t.Errorf("DefaultConfig().SampleRatio = %f, want %f", cfg.SampleRatio, 1.0)
	}
	if !cfg.Insecure {
		t.Errorf("DefaultConfig().Insecure = %v, want %v", cfg.Insecure, true)
	}
	if cfg.IsEnabled() {
		t.Errorf("DefaultConfig().IsEnabled() = true, want false")
	}
}

func TestSetup_DisabledTracing(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Endpoint: "", // Empty endpoint disables tracing
	}

	tp, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() error = %v, want nil", err)
	}
	if tp == nil {
		t.Fatal("Setup() returned nil TracerProvider")
	}

	// Verify we got a no-op tracer (provider should be nil)
	if tp.provider != nil {
		t.Error("Setup() with disabled tracing should have nil provider")
	}

	// Tracer should still work (returns global no-op tracer)
	tracer := tp.Tracer()
	if tracer == nil {
		t.Error("TracerProvider.Tracer() returned nil")
	}

	// Shutdown should work without error
	if err := tp.Shutdown(ctx); err != nil {
		t.Errorf("TracerProvider.Shutdown() error = %v, want nil", err)
	}
}

func TestSetup_InvalidProtocol(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Endpoint: "localhost:4317",
		Protocol: "invalid",
	}

	_, err := Setup(ctx, cfg)
	if err == nil {
		t.Error("Setup() with invalid protocol should return error")
	}
}

func TestTracerProvider_Shutdown_NilProvider(t *testing.T) {
	tp := &TracerProvider{
		provider: nil,
		tracer:   nil,
	}

	ctx := context.Background()
	if err := tp.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() with nil provider error = %v, want nil", err)
	}
}

func TestTracer(t *testing.T) {
	tracer := Tracer()
	if tracer == nil {
		t.Error("Tracer() returned nil")
	}
}

func TestStartSpan(t *testing.T) {
	ctx := context.Background()
	spanCtx, span := StartSpan(ctx, "test-span")

	if spanCtx == nil {
		t.Error("StartSpan() returned nil context")
	}
	if span == nil {
		t.Error("StartSpan() returned nil span")
	}

	span.End()
}

func TestStartSpan_WithAttributes(t *testing.T) {
	ctx := context.Background()
	spanCtx, span := StartSpan(ctx, "test-span-with-attrs",
		trace.WithAttributes(
			AttrImageName.String("nginx:latest"),
			AttrPodName.String("test-pod"),
		),
	)

	if spanCtx == nil {
		t.Error("StartSpan() returned nil context")
	}
	if span == nil {
		t.Error("StartSpan() returned nil span")
	}

	span.End()
}

func TestSpanFromContext(t *testing.T) {
	ctx := context.Background()

	// Get span from context without any span
	span := SpanFromContext(ctx)
	if span == nil {
		t.Error("SpanFromContext() returned nil for empty context")
	}

	// Create a span and verify we can retrieve it
	spanCtx, createdSpan := StartSpan(ctx, "test-span")
	defer createdSpan.End()

	retrievedSpan := SpanFromContext(spanCtx)
	if retrievedSpan == nil {
		t.Error("SpanFromContext() returned nil for context with span")
	}
}

func TestAttributeKeys(t *testing.T) {
	// Test that attribute keys create valid attributes
	tests := []struct {
		name string
		attr attribute.KeyValue
	}{
		{"image.name", AttrImageName.String("nginx:latest")},
		{"image.digest", AttrImageDigest.String("sha256:abc123")},
		{"pod.name", AttrPodName.String("test-pod")},
		{"pod.namespace", AttrPodNamespace.String("default")},
		{"scan.id", AttrScanID.String("scan-123")},
		{"scan.status", AttrScanStatus.String("completed")},
		{"scan.phase", AttrScanPhase.String("Passed")},
		{"aqua.registry", AttrAquaRegistry.String("docker.io")},
		{"aqua.endpoint", AttrAquaEndpoint.String("https://api.aqua.com")},
		{"http.method", AttrHTTPMethod.String("GET")},
		{"http.url", AttrHTTPURL.String("https://example.com/api")},
		{"http.status_code", AttrHTTPStatusCode.Int(200)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.attr.Key) != tt.name {
				t.Errorf("Attribute key = %q, want %q", tt.attr.Key, tt.name)
			}
			if !tt.attr.Valid() {
				t.Errorf("Attribute %q is not valid", tt.name)
			}
		})
	}
}

func TestTracerName(t *testing.T) {
	if TracerName != "aqua-scan-gate-controller" {
		t.Errorf("TracerName = %q, want %q", TracerName, "aqua-scan-gate-controller")
	}
}

func TestTracerProvider_Tracer(t *testing.T) {
	// Test with disabled tracing (nil provider)
	ctx := context.Background()
	cfg := Config{Endpoint: ""}

	tp, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	tracer := tp.Tracer()
	if tracer == nil {
		t.Error("TracerProvider.Tracer() returned nil")
	}
}
