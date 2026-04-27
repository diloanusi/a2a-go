# Feature: Custom Authentication Handler Extension
#
# User Story:
#   As a security-conscious developer using the A2A Go SDK,
#   I want to plug in a custom authentication handler,
#   So that I can enforce access control without modifying SDK internals.

Feature: Custom Authentication Handler Extension

  Background:
    Given the A2A server is initialized with a pluggable auth handler

  # ---------------------------------------------------------------------------
  # Acceptance Criteria 1 – Valid credentials are accepted
  # ---------------------------------------------------------------------------
  Scenario: Request with valid credentials is authenticated successfully
    Given a custom auth handler is registered that accepts token "valid-token-abc"
    And the incoming request carries the authorization header "Bearer valid-token-abc"
    When the server processes the request
    Then the request should be forwarded to the transport handler
    And no authentication error should be returned

  # ---------------------------------------------------------------------------
  # Acceptance Criteria 2 – Invalid credentials are rejected
  # ---------------------------------------------------------------------------
  Scenario: Request with invalid credentials is rejected
    Given a custom auth handler is registered that accepts token "valid-token-abc"
    And the incoming request carries the authorization header "Bearer wrong-token"
    When the server processes the request
    Then the request should be rejected before reaching the transport handler
    And an authentication error "unauthorized: invalid token" should be returned

  # ---------------------------------------------------------------------------
  # Acceptance Criteria 3 – Missing credentials are rejected
  # ---------------------------------------------------------------------------
  Scenario: Request with no authorization header is rejected
    Given a custom auth handler is registered that accepts token "valid-token-abc"
    And the incoming request carries no authorization header
    When the server processes the request
    Then the request should be rejected before reaching the transport handler
    And an authentication error "unauthorized: missing authorization header" should be returned

  # ---------------------------------------------------------------------------
  # Acceptance Criteria 4 – No auth handler registered allows all requests
  # ---------------------------------------------------------------------------
  Scenario: Request passes through when no auth handler is registered
    Given no custom auth handler is registered
    And the incoming request carries the authorization header "Bearer any-token"
    When the server processes the request
    Then the request should be forwarded to the transport handler
    And no authentication error should be returned

  # ---------------------------------------------------------------------------
  # Acceptance Criteria 5 – Auth handler can be swapped at runtime
  # ---------------------------------------------------------------------------
  Scenario: Replacing the auth handler takes immediate effect
    Given a custom auth handler is registered that accepts token "old-token"
    And the auth handler is replaced with one that accepts token "new-token"
    And the incoming request carries the authorization header "Bearer new-token"
    When the server processes the request
    Then the request should be forwarded to the transport handler
    And no authentication error should be returned

  # ---------------------------------------------------------------------------
  # Acceptance Criteria 6 – Auth handler error propagates cleanly
  # ---------------------------------------------------------------------------
  Scenario: Auth handler returns an internal error
    Given a custom auth handler is registered that always returns an internal error "auth service unavailable"
    And the incoming request carries the authorization header "Bearer valid-token-abc"
    When the server processes the request
    Then the request should be rejected before reaching the transport handler
    And an authentication error "auth service unavailable" should be returned

  # ---------------------------------------------------------------------------
  # Acceptance Criteria 7 – Auth handler receives full request context
  # ---------------------------------------------------------------------------
  Scenario: Auth handler receives the request metadata it needs to make decisions
    Given a custom auth handler is registered that inspects request metadata
    And the incoming request carries the authorization header "Bearer valid-token-abc"
    And the incoming request has metadata key "x-agent-id" with value "agent-007"
    When the server processes the request
    Then the auth handler should have received the header "Authorization" with value "Bearer valid-token-abc"
    And the auth handler should have received the metadata "x-agent-id" with value "agent-007"
    And no authentication error should be returned

  # ---------------------------------------------------------------------------
  # Exploratory – Edge cases not covered by acceptance criteria
  # ---------------------------------------------------------------------------

  Scenario: Request with wrong authorization scheme is rejected
    Given a custom auth handler is registered that accepts token "valid-token-abc"
    And the incoming request carries the authorization header "Token valid-token-abc"
    When the server processes the request
    Then the request should be rejected before reaching the transport handler
    And an authentication error "unauthorized: invalid token" should be returned

  Scenario: Request with bare Bearer keyword and no token is rejected
    Given a custom auth handler is registered that accepts token "valid-token-abc"
    And the incoming request carries the authorization header "Bearer"
    When the server processes the request
    Then the request should be rejected before reaching the transport handler
    And an authentication error "unauthorized: invalid token" should be returned

  Scenario: Request with empty authorization header string is rejected
    Given a custom auth handler is registered that accepts token "valid-token-abc"
    And the incoming request carries the authorization header ""
    When the server processes the request
    Then the request should be rejected before reaching the transport handler
    And an authentication error "unauthorized: missing authorization header" should be returned

  Scenario: Removing the auth handler restores pass-through for all requests
    Given a custom auth handler is registered that accepts token "valid-token-abc"
    And no custom auth handler is registered
    And the incoming request carries no authorization header
    When the server processes the request
    Then the request should be forwarded to the transport handler
    And no authentication error should be returned

  Scenario: All metadata entries are forwarded to the auth handler
    Given a custom auth handler is registered that inspects request metadata
    And the incoming request carries the authorization header "Bearer valid-token-abc"
    And the incoming request has metadata key "x-agent-id" with value "agent-007"
    And the incoming request has metadata key "x-tenant-id" with value "tenant-42"
    When the server processes the request
    Then the auth handler should have received the metadata "x-agent-id" with value "agent-007"
    And the auth handler should have received the metadata "x-tenant-id" with value "tenant-42"
    And no authentication error should be returned

  Scenario: Token comparison is case-sensitive
    Given a custom auth handler is registered that accepts token "Valid-Token-ABC"
    And the incoming request carries the authorization header "Bearer valid-token-abc"
    When the server processes the request
    Then the request should be rejected before reaching the transport handler
    And an authentication error "unauthorized: invalid token" should be returned

  Scenario: Token containing special characters is accepted when it matches exactly
    Given a custom auth handler is registered that accepts token "t0k3n!@#$%^&*()"
    And the incoming request carries the authorization header "Bearer t0k3n!@#$%^&*()"
    When the server processes the request
    Then the request should be forwarded to the transport handler
    And no authentication error should be returned
