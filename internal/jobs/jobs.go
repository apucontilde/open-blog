package jobs

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrDuplicate reports that a job with the same (kind, dedupe_key) already
// exists; re-enqueueing an idempotent operation is a caller-level no-op.
var ErrDuplicate = errors.New("jobs: duplicate dedupe_key")

// Enqueue inserts a job row inside the caller's transaction: a commit always
// carries its job, a rollback takes it with the rest of the domain write.
// dedupeKey empty disables dedupe (stored as NULL, outside the partial unique
// index); a non-empty duplicate key yields ErrDuplicate and inserts nothing.
func Enqueue(ctx context.Context, tx pgx.Tx, kind, dedupeKey string, payload any) (uuid.UUID, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `
		insert into jobs (kind, dedupe_key, payload)
		values ($1, nullif($2, ''), $3)
		on conflict (kind, dedupe_key) where dedupe_key is not null do nothing
		returning id`,
		kind, dedupeKey, b).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrDuplicate
	}
	return id, err
}

// EnqueueBatch inserts many jobs in one CopyFrom round trip. dedupe disabled
// for batch rows (bulk writes are already idempotent at the item level).
func EnqueueBatch(ctx context.Context, tx pgx.Tx, kind string, payloads []any) (int64, error) {
	rows := make([][]any, len(payloads))
	for i, p := range payloads {
		b, err := json.Marshal(p)
		if err != nil {
			return 0, err
		}
		rows[i] = []any{kind, b}
	}
	return tx.CopyFrom(ctx,
		pgx.Identifier{"jobs"},
		[]string{"kind", "payload"},
		pgx.CopyFromRows(rows))
}
