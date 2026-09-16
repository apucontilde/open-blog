package oauth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"openblog/internal/store"
)

// LinkIdentity idempotently links (provider, subject) to userID; a different owner is ErrIdentityTaken. New links require verified mailbox control.
func (o *OAuth) LinkIdentity(ctx context.Context, userID uuid.UUID, providerName, subject string) error {
	if userID == uuid.Nil {
		return ErrInvalidUserID
	}
	if subject == "" {
		return errors.New("oauth: identity subject is required")
	}
	return o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return linkIdentityTx(ctx, q, userID, providerName, subject)
	})
}

func linkIdentityTx(ctx context.Context, q *store.Queries, userID uuid.UUID, providerName, subject string) error {
	existing, err := q.GetIdentity(ctx, providerName, subject)
	if err == nil {
		if existing.UserID == userID {
			return nil
		}
		return ErrIdentityTaken
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := q.InsertIdentity(ctx, providerName, subject, userID); err != nil {
		// A concurrent login won the (provider, subject) PK; adopt it if same user.
		existing, err2 := q.GetIdentity(ctx, providerName, subject)
		if err2 == nil {
			if existing.UserID == userID {
				return nil
			}
			return ErrIdentityTaken
		}
		return err
	}
	return nil
}

// ConsumeInvitation atomically claims one live invitation; a repeat is ErrNoInvitation.
func (o *OAuth) ConsumeInvitation(ctx context.Context, email string, tenantID *uuid.UUID) (store.Invitation, error) {
	email = normalizeEmail(email)
	if email == "" {
		return store.Invitation{}, errors.New("oauth: email is required")
	}
	var inv store.Invitation
	err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		var err error
		inv, err = q.ConsumePendingInvitation(ctx, email, tenantID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Invitation{}, ErrNoInvitation
	}
	return inv, err
}
