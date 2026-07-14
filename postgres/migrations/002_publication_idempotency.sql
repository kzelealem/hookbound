-- hookbound:statement
ALTER TABLE hookbound_deliveries
    ADD COLUMN IF NOT EXISTS idempotency_key_hash bytea;

-- hookbound:statement
CREATE UNIQUE INDEX IF NOT EXISTS hookbound_deliveries_idempotency_key_idx
    ON hookbound_deliveries (idempotency_key_hash)
    WHERE idempotency_key_hash IS NOT NULL;
