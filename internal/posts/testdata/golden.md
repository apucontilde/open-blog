# Heading One

Paragraph with **bold**, *italic*, ~~strikethrough~~ and a [link](https://example.com) plus an email <mailto:a@b.com>.

## Code

```go
func main() {
	fmt.Println("hello")
}
```

## Table

| Left | Center | Right |
|:-----|:------:|------:|
| a    | b      | c     |

## Images

![ok](https://media.example.com/tenant/posts/abc/def.png)

![external](https://evil.example.com/x.png)

## Unsafe

<script>alert(1)</script>

[bad](javascript:alert(1))

![data](data:image/png;base64,AAAA)

<iframe src="https://evil.example.com"></iframe>

Bare URL: https://example.com/page.

> a quote

- one
- two

1. first
2. second

Inline `code` here.

- [x] done task
- [ ] open task

<hr>

<div class="x" onclick="bad()">div content</div>

<p onclick="bad()">para <b>bold raw</b></p>

[data](data:text/html,x)

<img src="javascript:alert(1)" onerror="bad()" alt="js">