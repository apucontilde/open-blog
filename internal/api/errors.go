package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"openblog/internal/auth"
	"openblog/internal/authz"
	"openblog/internal/import"
	"openblog/internal/media"
	"openblog/internal/oauth"
	"openblog/internal/posts"
)

const (
	codeNotFound     = "not_found"
	codeForbidden    = "forbidden"
	codeUnauthorized = "unauthorized"
	codeConflict     = "conflict"
	codeValidation   = "validation"
	codeInternal     = "internal"
	codeRateLimited  = "too_many_requests"
)

// errorEnvelope is the one error shape across the API; no internals leak.
type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: apiError{Code: code, Message: message}})
}

// mapError maps domain errors to (status, message); unknown errors become a 500.
func mapError(err error) (int, string) {
	switch {
	case errors.Is(err, posts.ErrNotFound),
		errors.Is(err, docimport.ErrNotFound),
		errors.Is(err, media.ErrImageNotFound),
		errors.Is(err, pgx.ErrNoRows):
		return http.StatusNotFound, "not found"
	case errors.Is(err, authz.ErrForbidden), errors.Is(err, posts.ErrNoTenant):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, posts.ErrSlugTaken),
		errors.Is(err, posts.ErrSlugImmutable),
		errors.Is(err, docimport.ErrAlreadyApplied),
		errors.Is(err, oauth.ErrIdentityTaken),
		errors.Is(err, oauth.ErrNoInvitation),
		errors.Is(err, auth.ErrInvited):
		return http.StatusConflict, "conflict"
	case errors.Is(err, posts.ErrEmptyContent),
		errors.Is(err, docimport.ErrNotConverted),
		errors.Is(err, docimport.ErrInvalidSource),
		errors.Is(err, media.ErrInvalidMime),
		errors.Is(err, media.ErrPayloadTooLarge),
		errors.Is(err, oauth.ErrUnknownProvider),
		errors.Is(err, oauth.ErrDisallowedRedirect):
		return http.StatusUnprocessableEntity, "validation failed"
	case errors.Is(err, oauth.ErrInvalidFlow),
		errors.Is(err, oauth.ErrProviderDenied),
		errors.Is(err, oauth.ErrExchangeFailed),
		errors.Is(err, oauth.ErrIdentityClaims),
		errors.Is(err, oauth.ErrUnverifiedEmail),
		errors.Is(err, oauth.ErrRefreshFailed),
		errors.Is(err, oauth.ErrNoToken),
		errors.Is(err, oauth.ErrScopeMissing):
		return http.StatusUnauthorized, "unauthorized"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}
