-- hookbound:statement
CREATE INDEX IF NOT EXISTS hookbound_deliveries_message_id_idx
    ON hookbound_deliveries (message_id);

-- hookbound:statement
CREATE INDEX IF NOT EXISTS hookbound_deliveries_terminal_cleanup_idx
    ON hookbound_deliveries (completed_at, id)
    WHERE state IN ('delivered','permanent_failure','disabled','exhausted');

-- hookbound:statement
CREATE INDEX IF NOT EXISTS hookbound_receipts_terminal_cleanup_idx
    ON hookbound_receipts (processed_at, source, message_id)
    WHERE state IN ('processed','failed','exhausted');

-- hookbound:statement
CREATE INDEX IF NOT EXISTS hookbound_messages_cleanup_idx
    ON hookbound_messages (created_at, id);
