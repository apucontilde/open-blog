package docimport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const (
	conversionTimeout = 10 * time.Second
	maxOutputBytes    = 2 << 20 // 2 MiB
)

// converter returns markdown and a fidelity level ("high" or "medium").
type converter func(ctx context.Context, src []byte) (md []byte, fidelity string, err error)

// Command and HTTP seams; tests inject fakes.
var (
	newCmd   = func(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
	lookPath = exec.LookPath
	httpDo   = func(req *http.Request) (*http.Response, error) { return http.DefaultClient.Do(req) }
)

// dispatch maps a source format to its converter.
func dispatch(format string) (converter, bool) {
	switch format {
	case "docx", "odt", "rtf", "html", "md":
		return pandocFor(format), true
	case "pdf":
		return pdftotext, true
	default:
		return nil, false
	}
}

// pandocFor binds pandoc to the source format so it parses the real input type.
func pandocFor(format string) converter {
	return func(ctx context.Context, src []byte) ([]byte, string, error) {
		return runPandoc(ctx, format, src)
	}
}

// runPandoc converts from the named source format with a 10s timeout and 2 MiB output cap; a missing binary is a setup error with a hint.
func runPandoc(ctx context.Context, from string, src []byte) ([]byte, string, error) {
	if from == "md" {
		from = "markdown"
	}
	pandocPath, err := lookPath("pandoc")
	if err != nil {
		return nil, "", fmt.Errorf("%w: pandoc not found; install pandoc or add to PATH", err)
	}
	ctx, cancel := context.WithTimeout(ctx, conversionTimeout)
	defer cancel()

	cmd := newCmd(pandocPath, "--wrap=none", "-f", from, "-t", "markdown")
	cmd.Stdin = bytes.NewReader(src)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{}

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("pandoc timed out after %s", conversionTimeout)
		}
		return nil, "", fmt.Errorf("pandoc failed: %w", err)
	}
	if stdout.Len() > maxOutputBytes {
		return nil, "", fmt.Errorf("pandoc output exceeds %d bytes", maxOutputBytes)
	}
	if stdout.Len() == 0 {
		return nil, "", errors.New("pandoc produced no output")
	}
	return stdout.Bytes(), "high", nil
}

// pdftotext runs pdftotext -layout; fidelity is "medium".
func pdftotext(ctx context.Context, src []byte) ([]byte, string, error) {
	pdftotextPath, err := lookPath("pdftotext")
	if err != nil {
		return nil, "", fmt.Errorf("%w: pdftotext not found; install poppler-utils or add to PATH", err)
	}
	ctx, cancel := context.WithTimeout(ctx, conversionTimeout)
	defer cancel()

	cmd := newCmd(pdftotextPath, "-layout", "-", "-")
	cmd.Stdin = bytes.NewReader(src)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{}

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("pdftotext timed out after %s", conversionTimeout)
		}
		return nil, "", fmt.Errorf("pdftotext failed: %w", err)
	}
	if stdout.Len() > maxOutputBytes {
		return nil, "", fmt.Errorf("pdftotext output exceeds %d bytes", maxOutputBytes)
	}
	if stdout.Len() == 0 {
		return nil, "", errors.New("pdftotext produced no output (scanned PDF?)")
	}

	text := stdout.Bytes()
	if isScannedPDF(text) {
		return nil, "", errors.New("scanned PDF detected: no text layer found; run OCR before importing")
	}
	return text, "medium", nil
}

// isScannedPDF treats very short or structural-marker-dominated output as having no text layer.
func isScannedPDF(text []byte) bool {
	trimmed := strings.TrimSpace(string(text))
	if len(trimmed) < 50 {
		return true
	}
	lines := strings.Split(trimmed, "\n")
	metaCount := 0
	for _, l := range lines {
		ls := strings.TrimSpace(l)
		if ls == "" || strings.HasPrefix(ls, "%") {
			metaCount++
		}
	}
	return metaCount > len(lines)*3/4
}

// gdocExport fetches the Doc as DOCX via the Drive v3 export endpoint then converts via pandoc; 401/403 → ErrGoogleToken.
func gdocExport(ctx context.Context, docID, accessToken string) ([]byte, string, error) {
	exportURL := fmt.Sprintf(
		"https://www.googleapis.com/drive/v3/files/%s/export?mimeType=application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		docID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exportURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("gdoc: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpDo(req)
	if err != nil {
		return nil, "", fmt.Errorf("gdoc: export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, "", fmt.Errorf("%w: Google token expired or drive.readonly not granted", ErrGoogleToken)
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("gdoc: export returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOutputBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("gdoc: read export: %w", err)
	}
	if int64(len(body)) > maxOutputBytes {
		return nil, "", fmt.Errorf("gdoc: exported DOCX exceeds %d bytes", maxOutputBytes)
	}

	return runPandoc(ctx, "docx", body)
}
