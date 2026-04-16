// Package logging provides leveled, module-tagged structured logging built on log/slog.
//
// Configure once at startup with Init, then call Module(name) anywhere to get a
// *slog.Logger whose records are tagged with module=<name> and filtered against
// that module's effective minimum level.
//
// Spec syntax (passed to Init): "<default>[,<module>=<level>]..."
// Example: "info,p2p=debug,wallet=warn"
//
// Levels: debug, info, warn, error (case-insensitive).
//
// Module() may be called from package-level var initializers (which run before
// flag parsing and Init): the returned *slog.Logger queries the live level
// table on every record, so a later Init call takes effect immediately.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	mu         sync.RWMutex
	defaultLvl = slog.LevelInfo
	perModule  = map[string]slog.Level{}

	// outputMode flips between console and JSON; sink is the destination Writer.
	// Both are atomic so handlers can read them lock-free per record.
	outputMode atomic.Int32 // 0 = console, 1 = json
	sink       atomic.Pointer[io.Writer]
	colorOn    atomic.Bool

	cache sync.Map // module name → *slog.Logger
)

func init() {
	w := io.Writer(os.Stderr)
	sink.Store(&w)
}

// effectiveLevel returns the configured level for module (or default).
func effectiveLevel(module string) slog.Level {
	mu.RLock()
	defer mu.RUnlock()
	if l, ok := perModule[module]; ok {
		return l
	}
	return defaultLvl
}

// Init configures the global logger. Safe to call once at startup.
// spec: "<default>[,<module>=<level>]...". Empty spec defaults to "info".
// json: when true, emit JSON records to stderr; otherwise pretty console output.
func Init(spec string, json bool) error {
	def, mods, err := ParseSpec(spec)
	if err != nil {
		return err
	}
	mu.Lock()
	defaultLvl = def
	perModule = mods
	mu.Unlock()
	if json {
		outputMode.Store(1)
		colorOn.Store(false)
	} else {
		outputMode.Store(0)
		w := sink.Load()
		if w != nil {
			if f, ok := (*w).(*os.File); ok {
				colorOn.Store(isTerminal(f))
			}
		}
	}
	return nil
}

// Module returns a logger tagged with module=name. Cached after first call.
// Safe to call before Init from var initializers; level is resolved per record.
func Module(name string) *slog.Logger {
	if v, ok := cache.Load(name); ok {
		return v.(*slog.Logger)
	}
	h := newDynamicHandler(name)
	l := slog.New(h)
	actual, _ := cache.LoadOrStore(name, l)
	return actual.(*slog.Logger)
}

// Fatal logs at ERROR through the named module then exits with code 1.
func Fatal(module, msg string, args ...any) {
	Module(module).Error(msg, args...)
	os.Exit(1)
}

// ParseLevel parses debug/info/warn/error (case-insensitive).
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "err":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("logging: unknown level %q", s)
}

// ParseSpec parses "<default>[,<module>=<level>]..." into a default level and
// per-module overrides. An empty spec yields (info, empty map).
func ParseSpec(spec string) (slog.Level, map[string]slog.Level, error) {
	def := slog.LevelInfo
	out := map[string]slog.Level{}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return def, out, nil
	}
	parts := strings.Split(spec, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "=") {
			if i != 0 {
				return 0, nil, fmt.Errorf("logging: bare level %q must come first", p)
			}
			lvl, err := ParseLevel(p)
			if err != nil {
				return 0, nil, err
			}
			def = lvl
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		mod := strings.TrimSpace(kv[0])
		lvl, err := ParseLevel(kv[1])
		if err != nil {
			return 0, nil, fmt.Errorf("logging: module %q: %w", mod, err)
		}
		if mod == "" {
			return 0, nil, fmt.Errorf("logging: empty module name in %q", p)
		}
		out[mod] = lvl
	}
	return def, out, nil
}
