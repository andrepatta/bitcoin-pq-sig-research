package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"
)

// ANSI color codes; emitted only when colorOn is set.
const (
	cReset  = "\x1b[0m"
	cRed    = "\x1b[31m"
	cYellow = "\x1b[33m"
	cBlue   = "\x1b[34m"
	cMag    = "\x1b[35m"
	cCyan   = "\x1b[36m"
	cGray   = "\x1b[90m"
)

// dynamicHandler is the slog.Handler returned by Module. It looks up the
// effective level on every Enabled/Handle call, so config changes via Init
// take effect for already-cached loggers (including those built from package
// var initializers that run before Init).
type dynamicHandler struct {
	module string
	attrs  []slog.Attr
	groups []string
}

func newDynamicHandler(module string) slog.Handler {
	return &dynamicHandler{module: module}
}

func (h *dynamicHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= effectiveLevel(h.module)
}

func (h *dynamicHandler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), as...)
	return &c
}

func (h *dynamicHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.groups = append(append([]string{}, h.groups...), name)
	return &c
}

func (h *dynamicHandler) Handle(ctx context.Context, r slog.Record) error {
	wp := sink.Load()
	if wp == nil {
		return nil
	}
	w := *wp
	if outputMode.Load() == 1 {
		return h.handleJSON(ctx, w, r)
	}
	return h.handleConsole(w, r)
}

func (h *dynamicHandler) handleJSON(ctx context.Context, w io.Writer, r slog.Record) error {
	// Build a fresh JSON handler per write; allocation cost is minor compared
	// to JSON encoding itself, and slog.NewJSONHandler is itself thread-safe.
	jh := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})
	inner := jh.WithAttrs([]slog.Attr{slog.String("module", h.module)})
	if len(h.attrs) > 0 {
		inner = inner.WithAttrs(h.attrs)
	}
	for _, g := range h.groups {
		inner = inner.WithGroup(g)
	}
	return inner.Handle(ctx, r)
}

var consoleMu sync.Mutex

func (h *dynamicHandler) handleConsole(w io.Writer, r slog.Record) error {
	color := colorOn.Load()

	var kvs []slog.Attr
	for _, a := range h.attrs {
		if a.Key == "module" {
			continue
		}
		kvs = append(kvs, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "module" {
			return true
		}
		kvs = append(kvs, a)
		return true
	})

	buf := make([]byte, 0, 128)
	buf = r.Time.AppendFormat(buf, "2006-01-02T15:04:05.000")
	buf = append(buf, ' ')

	lvlStr, lvlColor := levelMeta(r.Level)
	if color {
		buf = append(buf, lvlColor...)
		buf = append(buf, lvlStr...)
		buf = append(buf, cReset...)
	} else {
		buf = append(buf, lvlStr...)
	}
	buf = append(buf, ' ')

	const modWidth = 8
	if color {
		buf = append(buf, cCyan...)
	}
	buf = append(buf, '[')
	buf = appendPadded(buf, h.module, modWidth)
	buf = append(buf, ']')
	if color {
		buf = append(buf, cReset...)
	}
	buf = append(buf, ' ')

	buf = append(buf, r.Message...)

	for _, a := range kvs {
		buf = append(buf, ' ')
		if color {
			buf = append(buf, cGray...)
		}
		buf = append(buf, a.Key...)
		buf = append(buf, '=')
		if color {
			buf = append(buf, cReset...)
		}
		buf = appendValue(buf, a.Value)
	}
	buf = append(buf, '\n')

	consoleMu.Lock()
	_, err := w.Write(buf)
	consoleMu.Unlock()
	return err
}

func levelMeta(l slog.Level) (string, string) {
	switch {
	case l >= slog.LevelError:
		return "ERROR", cRed
	case l >= slog.LevelWarn:
		return "WARN ", cYellow
	case l >= slog.LevelInfo:
		return "INFO ", cBlue
	default:
		return "DEBUG", cMag
	}
}

func appendPadded(buf []byte, s string, width int) []byte {
	if len(s) >= width {
		return append(buf, s[:width]...)
	}
	buf = append(buf, s...)
	for i := len(s); i < width; i++ {
		buf = append(buf, ' ')
	}
	return buf
}

func appendValue(buf []byte, v slog.Value) []byte {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if needsQuote(s) {
			return strconv.AppendQuote(buf, s)
		}
		return append(buf, s...)
	case slog.KindInt64:
		return strconv.AppendInt(buf, v.Int64(), 10)
	case slog.KindUint64:
		return strconv.AppendUint(buf, v.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.AppendFloat(buf, v.Float64(), 'g', -1, 64)
	case slog.KindBool:
		return strconv.AppendBool(buf, v.Bool())
	case slog.KindDuration:
		return append(buf, v.Duration().String()...)
	case slog.KindTime:
		return v.Time().AppendFormat(buf, time.RFC3339Nano)
	default:
		return append(buf, fmt.Sprint(v.Any())...)
	}
}

func needsQuote(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r <= ' ' || r == '"' || r == '=' {
			return true
		}
	}
	return false
}

// isTerminal reports whether f is a terminal. Used to gate ANSI colors.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
