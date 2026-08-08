package libdnsspaceship

import (
	"fmt" // 新增导入，用于格式化日志消息
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"
)

// LogLevel defines the verbosity level of logging.
type LogLevel int

const (
	// LogLevelSilent disables all logging (default).
	LogLevelSilent LogLevel = iota
	// LogLevelError logs only errors.
	LogLevelError
	// LogLevelInfo logs errors and informational messages.
	LogLevelInfo
	// LogLevelDebug logs everything including detailed debug traces.
	LogLevelDebug
)

// Provider facilitates DNS record manipulation with Spaceship.
type Provider struct {
	// APIKey is the Spaceship API key for authentication
	APIKey string `json:"api_key,omitempty"`

	// APISecret is the Spaceship API secret for authentication
	APISecret string `json:"api_secret,omitempty"`

	// BaseURL is the base URL for the Spaceship API (defaults to https://spaceship.dev/api)
	BaseURL string `json:"base_url,omitempty"`

	// HTTPClient allows customization of the HTTP client used for API requests
	HTTPClient *http.Client `json:"-"`

	// PageSize controls pagination size used by GetRecords (defaults to 100)
	PageSize int `json:"page_size,omitempty"`

	// internal logger and log level
	logger   *slog.Logger
	logLevel LogLevel
}

// SetLogLevel sets the logging level. Available levels:
//   - LogLevelSilent: no output (default)
//   - LogLevelError: only errors
//   - LogLevelInfo: errors + informational messages
//   - LogLevelDebug: everything + detailed debug traces
func (p *Provider) SetLogLevel(level LogLevel) {
	p.logLevel = level
	p.logger = p.newLogger(level)
}

// newLogger creates a slog.Logger with the given level.
func (p *Provider) newLogger(level LogLevel) *slog.Logger {
	if level == LogLevelSilent {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var slogLevel slog.Level
	switch level {
	case LogLevelDebug:
		slogLevel = slog.LevelDebug
	case LogLevelInfo:
		slogLevel = slog.LevelInfo
	case LogLevelError:
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo + 1 // 高于 Error，实际不输出
	}
	opts := &slog.HandlerOptions{Level: slogLevel}
	handler := slog.NewTextHandler(os.Stdout, opts)
	return slog.New(handler)
}

// internal logging helpers
// 修改：使用 fmt.Sprintf 将格式化参数拼接成完整字符串，再传给 slog，避免键值对解析错误。
func (p *Provider) logDebug(format string, args ...any) {
	if p.logger != nil && p.logLevel >= LogLevelDebug {
		msg := format
		if len(args) > 0 {
			msg = fmt.Sprintf(format, args...)
		}
		p.logger.Debug(msg)
	}
}

func (p *Provider) logInfo(format string, args ...any) {
	if p.logger != nil && p.logLevel >= LogLevelInfo {
		msg := format
		if len(args) > 0 {
			msg = fmt.Sprintf(format, args...)
		}
		p.logger.Info(msg)
	}
}

func (p *Provider) logError(format string, args ...any) {
	if p.logger != nil && p.logLevel >= LogLevelError {
		msg := format
		if len(args) > 0 {
			msg = fmt.Sprintf(format, args...)
		}
		p.logger.Error(msg)
	}
}

// listResponse models the GET /v1/dns/records/{domain} response
type listResponse struct {
	Items []spaceshipRecordUnion `json:"items"`
	Total int                    `json:"total"`
}

// NewProviderFromEnv constructs a Provider using environment variables.
// Recognized environment variables:
// - LIBDNS_SPACESHIP_APIKEY: API key (required for API calls)
// - LIBDNS_SPACESHIP_APISECRET: API secret (required for API calls)
// - LIBDNS_SPACESHIP_BASEURL: optional base URL override
// - LIBDNS_SPACESHIP_PAGESIZE: optional page size for list operations
// - LIBDNS_SPACESHIP_TIMEOUT: optional HTTP client timeout in seconds
func NewProviderFromEnv() *Provider {
	p := &Provider{}
	p.PopulateFromEnv()
	// Initialize with silent level
	p.logger = p.newLogger(LogLevelSilent)
	p.logLevel = LogLevelSilent
	return p
}

// PopulateFromEnv fills unset Provider fields from environment variables.
func (p *Provider) PopulateFromEnv() {
	if p.APIKey == "" {
		p.APIKey = os.Getenv("LIBDNS_SPACESHIP_APIKEY")
	}
	if p.APISecret == "" {
		p.APISecret = os.Getenv("LIBDNS_SPACESHIP_APISECRET")
	}
	if p.BaseURL == "" {
		if v := os.Getenv("LIBDNS_SPACESHIP_BASEURL"); v != "" {
			p.BaseURL = v
		}
	}
	if p.PageSize == 0 {
		if v := os.Getenv("LIBDNS_SPACESHIP_PAGESIZE"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				p.PageSize = n
			}
		}
	}
	// If user hasn't provided HTTPClient and a timeout env var is present, set a client
	if p.HTTPClient == nil {
		if v := os.Getenv("LIBDNS_SPACESHIP_TIMEOUT"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				p.HTTPClient = &http.Client{Timeout: time.Duration(n) * time.Second}
			}
		}
	}
}
