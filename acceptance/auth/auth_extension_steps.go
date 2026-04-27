// Copyright 2026 The A2A Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package auth_test contains the step definitions for the Authentication
// Extension acceptance tests defined in features/auth_extension.feature.
package auth_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/cucumber/godog"
)

// ---------------------------------------------------------------------------
// Domain types  (mirrors the real A2A SDK interfaces)
// ---------------------------------------------------------------------------

// RequestContext holds the headers and metadata attached to an inbound request.
type RequestContext struct {
	Headers  map[string]string
	Metadata map[string]string
}

// AuthHandler is the pluggable interface SDK users implement to enforce auth.
// Returning a non-nil error rejects the request; nil allows it through.
type AuthHandler interface {
	Authenticate(ctx context.Context, req *RequestContext) error
}

// ---------------------------------------------------------------------------
// Server under test
// ---------------------------------------------------------------------------

// Server is a minimal stand-in for the real A2A server.
// It holds an optional AuthHandler and tracks whether the transport was reached.
type Server struct {
	authHandler     AuthHandler
	transportCalled bool
}

// SetAuthHandler registers (or replaces) the custom auth handler.
// Passing nil clears any previously registered handler.
func (s *Server) SetAuthHandler(h AuthHandler) {
	s.authHandler = h
}

// HandleRequest simulates the SDK request pipeline:
//  1. Run the auth handler (if registered).
//  2. Forward to transport if auth passes.
func (s *Server) HandleRequest(ctx context.Context, req *RequestContext) error {
	s.transportCalled = false

	if s.authHandler != nil {
		if err := s.authHandler.Authenticate(ctx, req); err != nil {
			return err
		}
	}

	s.transportCalled = true
	return nil
}

// ---------------------------------------------------------------------------
// Mock AuthHandler implementations
// ---------------------------------------------------------------------------

// tokenAuthHandler accepts exactly one hard-coded bearer token.
type tokenAuthHandler struct {
	acceptedToken string
}

func (h *tokenAuthHandler) Authenticate(_ context.Context, req *RequestContext) error {
	authHeader, ok := req.Headers["Authorization"]
	if !ok || authHeader == "" {
		return errors.New("unauthorized: missing authorization header")
	}
	if authHeader != "Bearer "+h.acceptedToken {
		return errors.New("unauthorized: invalid token")
	}
	return nil
}

// errorAuthHandler always returns a fixed internal error.
type errorAuthHandler struct {
	errMsg string
}

func (h *errorAuthHandler) Authenticate(_ context.Context, _ *RequestContext) error {
	return errors.New(h.errMsg)
}

// inspectingAuthHandler records received headers/metadata for assertion steps.
type inspectingAuthHandler struct {
	receivedHeaders  map[string]string
	receivedMetadata map[string]string
	acceptedToken    string
}

func (h *inspectingAuthHandler) Authenticate(_ context.Context, req *RequestContext) error {
	h.receivedHeaders = make(map[string]string)
	for k, v := range req.Headers {
		h.receivedHeaders[k] = v
	}
	h.receivedMetadata = make(map[string]string)
	for k, v := range req.Metadata {
		h.receivedMetadata[k] = v
	}

	authHeader, ok := req.Headers["Authorization"]
	if !ok {
		return errors.New("unauthorized: missing authorization header")
	}
	if authHeader != "Bearer "+h.acceptedToken {
		return errors.New("unauthorized: invalid token")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scenario state
// ---------------------------------------------------------------------------

// scenarioState holds all mutable state for a single scenario execution.
// A fresh instance is created for every scenario by InitializeScenario.
type scenarioState struct {
	server            *Server
	request           *RequestContext
	resultErr         error
	inspectingHandler *inspectingAuthHandler
}

func newScenarioState() *scenarioState {
	return &scenarioState{
		server: &Server{},
		request: &RequestContext{
			Headers:  make(map[string]string),
			Metadata: make(map[string]string),
		},
	}
}

// ---------------------------------------------------------------------------
// InitializeScenario registers all Gherkin steps with godog.
// Called by the test runner once per scenario.
// ---------------------------------------------------------------------------

func InitializeScenario(ctx *godog.ScenarioContext) {
	s := newScenarioState()

	// ── Background ────────────────────────────────────────────────────────────

	ctx.Step(`^the A2A server is initialized with a pluggable auth handler$`, func() {
		// Fresh state already initialised above; nothing extra needed.
	})

	// ── Given ─────────────────────────────────────────────────────────────────

	ctx.Step(`^a custom auth handler is registered that accepts token "([^"]*)"$`,
		func(token string) {
			s.server.SetAuthHandler(&tokenAuthHandler{acceptedToken: token})
		})

	ctx.Step(`^no custom auth handler is registered$`, func() {
		s.server.SetAuthHandler(nil)
	})

	ctx.Step(`^the auth handler is replaced with one that accepts token "([^"]*)"$`,
		func(token string) {
			s.server.SetAuthHandler(&tokenAuthHandler{acceptedToken: token})
		})

	ctx.Step(`^a custom auth handler is registered that always returns an internal error "([^"]*)"$`,
		func(errMsg string) {
			s.server.SetAuthHandler(&errorAuthHandler{errMsg: errMsg})
		})

	ctx.Step(`^a custom auth handler is registered that inspects request metadata$`, func() {
		s.inspectingHandler = &inspectingAuthHandler{acceptedToken: "valid-token-abc"}
		s.server.SetAuthHandler(s.inspectingHandler)
	})

	ctx.Step(`^the incoming request carries the authorization header "([^"]*)"$`,
		func(headerValue string) {
			s.request.Headers["Authorization"] = headerValue
		})

	ctx.Step(`^the incoming request carries no authorization header$`, func() {
		delete(s.request.Headers, "Authorization")
	})

	ctx.Step(`^the incoming request has metadata key "([^"]*)" with value "([^"]*)"$`,
		func(key, value string) {
			s.request.Metadata[key] = value
		})

	// ── When ──────────────────────────────────────────────────────────────────

	ctx.Step(`^the server processes the request$`, func() {
		s.resultErr = s.server.HandleRequest(context.Background(), s.request)
	})

	// ── Then ──────────────────────────────────────────────────────────────────

	ctx.Step(`^the request should be forwarded to the transport handler$`, func() error {
		if !s.server.transportCalled {
			return fmt.Errorf("expected transport handler to be called, but it was not")
		}
		return nil
	})

	ctx.Step(`^the request should be rejected before reaching the transport handler$`,
		func() error {
			if s.server.transportCalled {
				return fmt.Errorf("expected transport handler NOT to be called, but it was")
			}
			return nil
		})

	ctx.Step(`^no authentication error should be returned$`, func() error {
		if s.resultErr != nil {
			return fmt.Errorf("expected no error but got: %v", s.resultErr)
		}
		return nil
	})

	ctx.Step(`^an authentication error "([^"]*)" should be returned$`,
		func(expectedMsg string) error {
			if s.resultErr == nil {
				return fmt.Errorf("expected error containing %q but got nil", expectedMsg)
			}
			if !containsString(s.resultErr.Error(), expectedMsg) {
				return fmt.Errorf(
					"expected error to contain %q, got %q",
					expectedMsg, s.resultErr.Error(),
				)
			}
			return nil
		})

	ctx.Step(`^the auth handler should have received the header "([^"]*)" with value "([^"]*)"$`,
		func(key, expectedValue string) error {
			if s.inspectingHandler == nil {
				return fmt.Errorf("inspecting handler was not registered")
			}
			got, ok := s.inspectingHandler.receivedHeaders[key]
			if !ok {
				return fmt.Errorf("auth handler did not receive header %q", key)
			}
			if got != expectedValue {
				return fmt.Errorf("expected header %q = %q, got %q", key, expectedValue, got)
			}
			return nil
		})

	ctx.Step(`^the auth handler should have received the metadata "([^"]*)" with value "([^"]*)"$`,
		func(key, expectedValue string) error {
			if s.inspectingHandler == nil {
				return fmt.Errorf("inspecting handler was not registered")
			}
			got, ok := s.inspectingHandler.receivedMetadata[key]
			if !ok {
				return fmt.Errorf("auth handler did not receive metadata key %q", key)
			}
			if got != expectedValue {
				return fmt.Errorf(
					"expected metadata %q = %q, got %q", key, expectedValue, got)
			}
			return nil
		})
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func containsString(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
