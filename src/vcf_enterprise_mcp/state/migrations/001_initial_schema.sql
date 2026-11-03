-- PostgreSQL DDL for Enterprise VCF MCP Control Plane
-- Schema Migration: 001_initial_schema.sql

CREATE TABLE IF NOT EXISTS tasks (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    task_id VARCHAR(128) NOT NULL,
    principal_id VARCHAR(256) NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    status VARCHAR(64) NOT NULL,
    progress DOUBLE PRECISION DEFAULT 0.0,
    step VARCHAR(256) DEFAULT '',
    native_task_id VARCHAR(256) DEFAULT '',
    steps_json TEXT DEFAULT '[]',
    metadata_json TEXT DEFAULT '{}',
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, task_id)
);

CREATE TABLE IF NOT EXISTS workflow_instances (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    workflow_id VARCHAR(128) NOT NULL,
    principal_id VARCHAR(256) NOT NULL,
    state VARCHAR(64) NOT NULL,
    context_json TEXT DEFAULT '{}',
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, workflow_id)
);

CREATE TABLE IF NOT EXISTS workflow_steps (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    workflow_id VARCHAR(128) NOT NULL,
    step_id VARCHAR(128) NOT NULL,
    state VARCHAR(64) NOT NULL,
    input_json TEXT DEFAULT '{}',
    output_json TEXT DEFAULT '{}',
    error_message TEXT DEFAULT '',
    updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, workflow_id, step_id)
);

CREATE TABLE IF NOT EXISTS execution_plans (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    plan_id VARCHAR(128) NOT NULL,
    principal_id VARCHAR(256) NOT NULL,
    tool_id VARCHAR(128) NOT NULL,
    args_sha256 VARCHAR(64) NOT NULL,
    normalized_args_json TEXT NOT NULL,
    resource_revisions_json TEXT NOT NULL,
    impact_summary_json TEXT NOT NULL,
    permission_epoch INTEGER NOT NULL,
    status VARCHAR(64) NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, plan_id)
);

CREATE TABLE IF NOT EXISTS approvals (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    approval_id VARCHAR(128) NOT NULL,
    plan_id VARCHAR(128) NOT NULL,
    approver_id VARCHAR(256) NOT NULL,
    approver_roles TEXT DEFAULT '[]',
    nonce VARCHAR(128) NOT NULL,
    issued_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    permission_epoch INTEGER NOT NULL DEFAULT 100,
    signature TEXT DEFAULT '',
    key_id VARCHAR(128) DEFAULT '',
    algorithm VARCHAR(32) DEFAULT 'RS256',
    used INTEGER DEFAULT 0,
    status VARCHAR(64) DEFAULT 'VALID',
    PRIMARY KEY (tenant_id, environment_id, approval_id)
);

CREATE TABLE IF NOT EXISTS approval_nonces (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    approval_id VARCHAR(128) NOT NULL,
    issued_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    consumed_at DOUBLE PRECISION,
    PRIMARY KEY (tenant_id, environment_id, nonce)
);

CREATE TABLE IF NOT EXISTS idempotency_records (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    principal_id VARCHAR(256) NOT NULL,
    tool_id VARCHAR(128) NOT NULL,
    args_sha256 VARCHAR(64) NOT NULL,
    status VARCHAR(32) DEFAULT 'COMMITTED',
    response_json TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS idempotency (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    principal_id VARCHAR(256) NOT NULL,
    tool_id VARCHAR(128) NOT NULL,
    args_sha256 VARCHAR(64) NOT NULL,
    status VARCHAR(32) DEFAULT 'COMMITTED',
    response_json TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS resource_leases (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    resource_id VARCHAR(256) NOT NULL,
    lease_holder VARCHAR(256) NOT NULL,
    lease_type VARCHAR(64) NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 1,
    acquired_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, resource_id)
);

CREATE TABLE IF NOT EXISTS leases (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    resource_id VARCHAR(256) NOT NULL,
    lease_holder VARCHAR(256) NOT NULL,
    lease_type VARCHAR(64) NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 1,
    acquired_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, resource_id)
);

CREATE TABLE IF NOT EXISTS fencing_counters (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    resource_id VARCHAR(256) NOT NULL,
    last_token BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, environment_id, resource_id)
);

CREATE TABLE IF NOT EXISTS execution_intents (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    intent_id VARCHAR(128) NOT NULL,
    workflow_id VARCHAR(128) NOT NULL,
    step_id VARCHAR(128) NOT NULL,
    state VARCHAR(64) NOT NULL,
    target_resource VARCHAR(256) NOT NULL,
    operation_id VARCHAR(128) NOT NULL,
    desired_state_json TEXT NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    recorded_at DOUBLE PRECISION NOT NULL,
    resolved_at DOUBLE PRECISION DEFAULT 0.0,
    outcome TEXT DEFAULT '',
    PRIMARY KEY (tenant_id, environment_id, intent_id)
);

CREATE TABLE IF NOT EXISTS permission_epochs (
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    epoch BIGINT NOT NULL DEFAULT 100,
    updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, environment_id)
);

CREATE TABLE IF NOT EXISTS principal_epochs (
    tenant_id VARCHAR(128) NOT NULL,
    principal_id VARCHAR(256) NOT NULL,
    epoch BIGINT NOT NULL DEFAULT 100,
    updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, principal_id)
);

CREATE TABLE IF NOT EXISTS policy_epochs (
    tenant_id VARCHAR(128) NOT NULL,
    epoch BIGINT NOT NULL DEFAULT 100,
    updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS audit_records (
    seq_id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    record_payload TEXT NOT NULL,
    timestamp DOUBLE PRECISION NOT NULL,
    UNIQUE (tenant_id, environment_id, event_id)
);

CREATE TABLE IF NOT EXISTS audit_chain (
    seq_id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    record_payload TEXT NOT NULL,
    timestamp DOUBLE PRECISION NOT NULL,
    UNIQUE (tenant_id, environment_id, event_id)
);

CREATE TABLE IF NOT EXISTS audit_anchors (
    anchor_id VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    chain_head_hash VARCHAR(64) NOT NULL,
    external_target VARCHAR(128) NOT NULL,
    anchored_at DOUBLE PRECISION NOT NULL,
    verification_proof TEXT NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, anchor_id)
);

CREATE TABLE IF NOT EXISTS outbox_events (
    event_id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    environment_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    payload_json TEXT NOT NULL,
    status VARCHAR(32) DEFAULT 'PENDING',
    created_at DOUBLE PRECISION NOT NULL,
    published_at DOUBLE PRECISION
);
