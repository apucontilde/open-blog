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

// errorEnvelope is the ONLY error shape across the API; no stack traces escape.
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

// mapError maps domain errors to (status, message); anything unrecognized is a
// 500 with no internals leaked.
func mapError(err error) (int, string) {
	switch {
	case errors.Is(err, posts.ErrNotFound),
		errors.Is(err, docimport.ErrNotFound),
		errors.Is(err, media.ErrImageNotFound),
		errors.Is(err, pgx.ErrNoRows):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, authz.ErrForbidden), errors.Is(err, posts.ErrNoTenant):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, posts.ErrSlugTaken),
		errors.Is(err, posts.ErrSlugImmutable),
		errors.Is(err, docimport.ErrAlreadyApplied),
		errors.Is(err, oauth.ErrIdentityTaken),
		errors.Is(err, oauth.ErrNoInvitation),
		errors.Is(err, auth.ErrInvited):
		return http.StatusConflict, err.Error()
	case errors.Is(err, posts.ErrEmptyContent),
		errors.Is(err, docimport.ErrNotConverted),
		errors.Is(err, docimport.ErrInvalidSource),
		errors.Is(err, media.ErrInvalidMime),
		errors.Is(err, media.ErrPayloadTooLarge),
		errors.Is(err, oauth.ErrUnknownProvider),
		errors.Is(err, oauth.ErrDisallowedRedirect):
		return http.StatusUnprocessableEntity, err.Error()
	case errors.Is(err, oauth.ErrInvalidFlow),
		errors.Is(err, oauth.ErrProviderDenied),
		errors.Is(err, oauth.ErrExchangeFailed),
		errors.Is(err, oauth.ErrIdentityClaims),
		errors.Is(err, oauth.ErrUnverifiedEmail),
		errors.Is(err, oauth.ErrRefreshFailed),
		errors.Is(err, oauth.ErrNoToken),
		errors.Is(err, oauth.ErrScopeMissing):
		return http.StatusUnauthorized, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}
