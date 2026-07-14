-- hookbound:statement
CREATE TABLE IF NOT EXISTS hookbound_messages (
    id              text PRIMARY KEY,
    event_type      text NOT NULL,
    body            bytea NOT NULL,
    content_type    text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- hookbound:statement
CREATE TABLE IF NOT EXISTS hookbound_deliveries (
    id                  text PRIMARY KEY,
    message_id          text NOT NULL REFERENCES hookbound_messages(id) ON DELETE CASCADE,
    destination_url     text NOT NULL,
    headers             jsonb NOT NULL DEFAULT '{}',
    state               text NOT NULL CHECK (state IN ('pending','in_flight','retry','delivered','permanent_failure','disabled','exhausted')),
    attempt_count       integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at     timestamptz NOT NULL DEFAULT now(),
    lease_expires_at    timestamptz,
    last_status_code    integer,
    last_error_code     text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    completed_at        timestamptz
);

-- hookbound:statement
CREATE INDEX IF NOT EXISTS hookbound_deliveries_due_idx
    ON hookbound_deliveries (next_attempt_at, created_at)
    WHERE state IN ('pending','retry');

-- hookbound:statement
CREATE INDEX IF NOT EXISTS hookbound_deliveries_lease_idx
    ON hookbound_deliveries (lease_expires_at)
    WHERE state = 'in_flight';

-- hookbound:statement
CREATE TABLE IF NOT EXISTS hookbound_attempts (
    id                  text PRIMARY KEY,
    delivery_id         text NOT NULL REFERENCES hookbound_deliveries(id) ON DELETE CASCADE,
    attempt_number      integer NOT NULL CHECK (attempt_number > 0),
    started_at          timestamptz NOT NULL,
    finished_at         timestamptz,
    outcome             text,
    status_code         integer,
    duration_ns         bigint,
    error_code          text,
    error_detail        text,
    response_headers    jsonb,
    response_body       bytea,
    next_attempt_at     timestamptz,
    UNIQUE (delivery_id, attempt_number)
);

-- hookbound:statement
CREATE TABLE IF NOT EXISTS hookbound_receipts (
    source              text NOT NULL,
    message_id          text NOT NULL,
    event_type          text NOT NULL,
    event_timestamp     timestamptz NOT NULL,
    body                bytea NOT NULL,
    content_type        text NOT NULL,
    headers             jsonb NOT NULL DEFAULT '{}',
    metadata            jsonb NOT NULL DEFAULT '{}',
    state               text NOT NULL CHECK (state IN ('pending','processing','retry','processed','failed','exhausted')),
    attempt_count       integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at     timestamptz NOT NULL DEFAULT now(),
    lease_expires_at    timestamptz,
    last_error_code     text,
    last_error_detail   text,
    received_at         timestamptz NOT NULL DEFAULT now(),
    processed_at        timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, message_id)
);

-- hookbound:statement
CREATE INDEX IF NOT EXISTS hookbound_receipts_due_idx
    ON hookbound_receipts (next_attempt_at, received_at)
    WHERE state IN ('pending','retry');

-- hookbound:statement
CREATE INDEX IF NOT EXISTS hookbound_receipts_lease_idx
    ON hookbound_receipts (lease_expires_at)
    WHERE state = 'processing';
