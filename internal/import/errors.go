package docimport

import "errors"

var (
	// ErrAlreadyApplied: imports.post_id already set (apply idempotency gate).
	ErrAlreadyApplied = errors.New("import: already applied to a draft")
	// ErrNotFound: import row absent or outside the actor's scope.
	ErrNotFound = errors.New("import: not found")
	// ErrInvalidSource: Start with neither file bytes nor a Google Doc ID.
	ErrInvalidSource = errors.New("import: provide file bytes or a Google Doc ID")
	// ErrNotConverted: Apply before conversion finished.
	ErrNotConverted = errors.New("import: not converted yet")
	// ErrGoogleToken: user's Google token absent/expired or missing drive.readonly.
	ErrGoogleToken = errors.New("import: Google re-consent required")
)
