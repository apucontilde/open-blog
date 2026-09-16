// Package migrations embeds the append-only SQL migration files in version order.
//
// FS is the file set goose runs via SetBaseFS (cmd/migrate) and that the RLS
// contract tests replay into scratch databases.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
