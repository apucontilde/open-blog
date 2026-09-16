package docimport

import "errors"

var (
	// ErrAlreadyApplied reports that imports.post_id is already set — the
	// idempotency gate for Apply (sweep 007 Q2: re-apply is refused when a
	// draft exists).
	ErrAlreadyApplied = errors.New("import: already applied to a draft")
	// ErrNotFound reports an import row absent or outside the actor's scope.
	ErrNotFound = errors.New("import: not found")
	// ErrInvalidSource reports a Start call with neither file bytes nor a
	// Google Doc ID.
	ErrInvalidSource = errors.New("import: provide file bytes or a Google Doc ID")
	// ErrNotConverted reports Apply called before conversion finished.
	ErrNotConverted = errors.New("import: not converted yet")
	// ErrGoogleToken reports that the user's Google token is absent, expired,
	// or missing the drive.readonly scope — re-consent is required.
	ErrGoogleToken = errors.New("import: Google re-consent required")
)
