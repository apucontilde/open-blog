package posts

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	gmdhtml "github.com/yuin/goldmark/renderer/html"
	nethtml "golang.org/x/net/html"
)

const defaultMediaOrigin = "media.example.com"

// renderer converts markdown to stored content_html: GFM + chroma highlighting
// on fenced code only, then sanitization to a fixed element allow-list. Output
// is deterministic (no clock, random state, or external process).
type renderer struct {
	md       goldmark.Markdown
	imgHosts []string // exact host allow-list; nil => any http(s) host (metadata opt-in)
}

func newRenderer(imgHosts []string) renderer {
	return renderer{
		md: goldmark.New(
			goldmark.WithExtensions(
				extension.GFM,
				extension.Linkify,
				highlighting.NewHighlighting(highlighting.WithStyle("github")),
			),
			// Raw author HTML must reach the sanitizer, the single gate;
			// without WithUnsafe goldmark drops it and golden parity diverges.
			goldmark.WithRendererOptions(gmdhtml.WithUnsafe()),
		),
		imgHosts: imgHosts,
	}
}

func (r renderer) render(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := r.md.Convert(src, &buf); err != nil {
		return nil, fmt.Errorf("posts: render: %w", err)
	}
	return sanitize(buf.Bytes(), r.imgHosts), nil
}

// renderGFM is the canonical render entry point: images restricted to media.example.com.
func renderGFM(md []byte) ([]byte, error) {
	return renderGFMHosts(md, []string{defaultMediaOrigin})
}

// renderGFMHosts: a non-empty imgHosts is an exact allow-list; nil allows any
// http(s) image.
func renderGFMHosts(md []byte, imgHosts []string) ([]byte, error) {
	return newRenderer(imgHosts).render(md)
}

// sanitize filters rendered HTML against the element/attribute allow-list and
// image-host policy; the single gate for every render path, raw HTML included.
func sanitize(in []byte, imgHosts []string) []byte {
	doc, err := nethtml.Parse(bytes.NewReader(in))
	if err != nil {
		return nil // fail closed
	}
	out := &nethtml.Node{Type: nethtml.ElementNode, Data: "div"}
	for c := documentBody(doc).FirstChild; c != nil; c = c.NextSibling {
		appendSanitized(out, c, imgHosts)
	}
	var buf bytes.Buffer
	if err := nethtml.Render(&buf, out); err != nil {
		return nil
	}
	s := buf.String()
	return []byte(s[len("<div>") : len(s)-len("</div>")])
}

func documentBody(doc *nethtml.Node) *nethtml.Node {
	var body *nethtml.Node
	var walk func(n *nethtml.Node)
	walk = func(n *nethtml.Node) {
		if body != nil {
			return
		}
		if n.Type == nethtml.ElementNode && n.Data == "body" {
			body = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if body == nil {
		return doc
	}
	return body
}

var (
	allowedTags = map[string]bool{
		"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
		"p": true, "br": true, "hr": true, "blockquote": true,
		"ul": true, "ol": true, "li": true,
		"strong": true, "em": true, "del": true, "s": true,
		"b": true, "i": true, "sub": true, "sup": true,
		"a": true, "img": true,
		"pre": true, "code": true, "span": true, "div": true,
		"table": true, "thead": true, "tbody": true, "tfoot": true,
		"tr": true, "th": true, "td": true, "input": true, // input = GFM task list
	}
	dangerousTags = map[string]bool{
		"script": true, "style": true, "iframe": true, "frame": true,
		"frameset": true, "object": true, "embed": true, "applet": true,
		"param": true, "form": true, "button": true, "select": true,
		"option": true, "textarea": true, "template": true, "noscript": true,
		"link": true, "meta": true, "base": true, "svg": true, "math": true,
		"video": true, "audio": true, "source": true, "track": true,
		"canvas": true,
	}
)

func appendSanitized(parent, n *nethtml.Node, imgHosts []string) {
	if n.Type == nethtml.TextNode {
		parent.AppendChild(&nethtml.Node{Type: nethtml.TextNode, Data: n.Data})
		return
	}
	if n.Type != nethtml.ElementNode {
		return
	}
	tag := n.Data
	if dangerousTags[tag] {
		return // drop the subtree
	}
	if !allowedTags[tag] {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			appendSanitized(parent, c, imgHosts)
		}
		return
	}
	if tag == "img" && !imgSrcAllowed(n.Attr, imgHosts) {
		return // rejected image: drop whole, not unwrap
	}
	e := &nethtml.Node{Type: nethtml.ElementNode, Data: tag, DataAtom: n.DataAtom}
	for _, a := range n.Attr {
		if allowedAttr(tag, a.Key, a.Val) {
			e.Attr = append(e.Attr, a)
		}
	}
	parent.AppendChild(e)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		appendSanitized(e, c, imgHosts)
	}
}

func allowedAttr(tag, key, val string) bool {
	key = strings.ToLower(key)
	switch tag {
	case "a":
		switch key {
		case "href":
			return safeLinkURL(val)
		case "title":
			return true
		}
	case "img":
		switch key {
		case "src":
			return safeImageURL(val)
		case "alt", "title":
			return true
		case "width", "height":
			return digitsRe.MatchString(val)
		}
	case "pre":
		switch key {
		case "style":
			return safeStyle(val)
		case "tabindex":
			return digitsRe.MatchString(val) // chroma emits <pre tabindex="0">
		case "class":
			return classOK(val)
		}
	case "code", "span", "div":
		switch key {
		case "class":
			return classOK(val)
		case "style":
			return safeStyle(val)
		}
	case "li":
		if key == "class" { // GFM task lists: class="task-list-item"
			return classOK(val)
		}
	case "th", "td":
		switch key {
		case "align": // GFM table alignment (XHTML path)
			return val == "left" || val == "center" || val == "right" || val == "justify" || val == "char"
		case "style": // GFM table alignment (HTML5 path)
			return safeStyle(val)
		case "rowspan", "colspan":
			return digitsRe.MatchString(val)
		}
	case "input": // GFM task list checkbox only
		switch key {
		case "type":
			return val == "checkbox"
		case "checked", "disabled":
			return true
		}
	}
	return false
}

func imgSrcAllowed(attrs []nethtml.Attribute, imgHosts []string) bool {
	for _, a := range attrs {
		if strings.EqualFold(a.Key, "src") {
			return safeImageURL(a.Val) && imageHostAllowed(a.Val, imgHosts)
		}
	}
	return false
}

func imageHostAllowed(u string, imgHosts []string) bool {
	if imgHosts == nil {
		return true // metadata opted in: any http(s) image
	}
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	host := strings.ToLower(p.Host)
	for _, h := range imgHosts {
		if host == strings.ToLower(h) {
			return true
		}
	}
	return false
}

func safeLinkURL(u string) bool {
	if u == "" || strings.TrimSpace(u) != u {
		return false
	}
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	switch strings.ToLower(p.Scheme) {
	case "http", "https", "mailto":
		return true
	case "":
		// relative only: no protocol-relative authority, no opaque scheme
		return p.Host == "" && !strings.HasPrefix(u, "//")
	}
	return false
}

func safeImageURL(u string) bool {
	if u == "" || strings.TrimSpace(u) != u {
		return false
	}
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(p.Scheme)
	return (scheme == "http" || scheme == "https") && p.Host != ""
}

var (
	digitsRe   = regexp.MustCompile(`^[0-9]+$`)
	classRe    = regexp.MustCompile(`^[a-zA-Z0-9 _-]+$`)
	styleRe    = regexp.MustCompile(`^[a-z][a-z-]*\s*(:\s*[a-zA-Z0-9 #.%+-]+)?$`)
	styleProps = map[string]bool{
		"color": true, "background-color": true, "font-weight": true,
		"font-style": true, "text-decoration": true, "white-space": true,
		"user-select": true, "margin-right": true, "padding": true,
		"display": true, "tab-width": true, "border-spacing": true,
		"vertical-align": true, "margin": true, "border": true,
		"float": true, "clear": true, "text-align": true,
	}
)

func classOK(s string) bool {
	return s != "" && len(s) <= 256 && classRe.MatchString(s)
}

// safeStyle allows only whitelisted properties with bare values (no url()/var(),
// quotes, slashes, or control chars).
func safeStyle(s string) bool {
	if s == "" || len(s) > 512 {
		return false
	}
	for _, decl := range strings.Split(s, ";") {
		decl = strings.TrimSpace(decl)
		if decl == "" {
			continue
		}
		m := styleRe.FindStringSubmatch(decl)
		if m == nil {
			return false
		}
		prop := strings.TrimSpace(strings.SplitN(decl, ":", 2)[0])
		if !styleProps[prop] {
			return false
		}
	}
	return true
}
