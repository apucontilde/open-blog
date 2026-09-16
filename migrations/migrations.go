package migrations

import "embed"

// FS is the embedded append-only, DDL-only migration set; never `if not exists`.
//
//go:embed *.sql
var FS embed.FS
