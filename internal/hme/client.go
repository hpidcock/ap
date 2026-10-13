// Package hme is the Hide My Email (iCloud+ alias) client - a thin read-only JSON REST
// layer authed purely by the web session's cookies - plus its encrypted local cache.
package hme

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hpidcock/ap/internal/paths"
	"github.com/hpidcock/ap/internal/securestore"
)

// Error is an alias API failure.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Alias is one Hide My Email address.
type Alias struct {
	AnonymousID string  `json:"anonymous_id"`
	Address     string  `json:"address"`
	Label       string  `json:"label"`
	Note        string  `json:"note"`
	ForwardTo   string  `json:"forward_to"`
	IsActive    bool    `json:"is_active"`
	Domain      string  `json:"domain"`
	CreatedAt   float64 `json:"created_at"` // unix seconds
}

// PublicDict is the view handed to the browser extension.
func (a Alias) PublicDict() map[string]any {
	return map[string]any{"address": a.Address, "label": a.Label, "domain": a.Domain}
}

// Client lists aliases through a cookie-bearing HTTP client.
type Client struct {
	v2   string
	HTTP *http.Client
}

// NewClient returns a client for the premiummailsettings base URL.
func NewClient(baseURL string, httpClient *http.Client) *Client {
	return &Client{v2: strings.TrimRight(baseURL, "/") + "/v2", HTTP: httpClient}
}

func errorDetail(data map[string]any) string {
	switch e := data["error"].(type) {
	case map[string]any:
		for _, k := range []string{"errorMessage", "message"} {
			if s, ok := e[k].(string); ok && s != "" {
				return s
			}
		}
		return fmt.Sprint(e)
	case nil:
	default:
		return fmt.Sprint(e)
	}
	for _, k := range []string{"errorMessage", "message"} {
		if s, ok := data[k].(string); ok && s != "" {
			return s
		}
	}
	return fmt.Sprint(data)
}

// List fetches every alias.
func (c *Client) List() ([]Alias, error) {
	req, err := http.NewRequest(http.MethodGet, c.v2+"/hme/list", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://www.icloud.com")
	req.Header.Set("Referer", "https://www.icloud.com/")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &Error{Msg: fmt.Sprintf("hme/list: %v", err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil {
		return nil, &Error{Msg: fmt.Sprintf("non-JSON response from hme/list (HTTP %d)", resp.StatusCode)}
	}
	success, _ := data["success"].(bool)
	if resp.StatusCode/100 != 2 || !success {
		return nil, &Error{Msg: fmt.Sprintf("hme/list failed (HTTP %d): %s", resp.StatusCode, errorDetail(data))}
	}
	result, _ := data["result"].(map[string]any)
	entries, _ := result["hmeEmails"].([]any)
	var out []Alias
	for _, e := range entries {
		m, _ := e.(map[string]any)
		if m != nil {
			out = append(out, parse(m))
		}
	}
	return out, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func parse(e map[string]any) Alias {
	ts, _ := e["createTimestamp"].(float64)
	active, _ := e["isActive"].(bool)
	return Alias{
		AnonymousID: str(e["anonymousId"]),
		Address:     str(e["hme"]),
		Label:       str(e["label"]),
		Note:        str(e["note"]),
		ForwardTo:   str(e["forwardToEmail"]),
		IsActive:    active,
		Domain:      str(e["domain"]),
		CreatedAt:   ts / 1000,
	}
}

// SaveAliases writes the encrypted alias cache read by the native host.
func SaveAliases(aliases []Alias) error {
	if aliases == nil {
		aliases = []Alias{}
	}
	data, err := json.Marshal(map[string]any{"aliases": aliases})
	if err != nil {
		return err
	}
	return securestore.WriteFile(paths.AliasesFile(), data)
}

// LoadAliases reads the cache; an undecryptable cache is discarded.
func LoadAliases() ([]Alias, error) {
	data, err := securestore.ReadFile(paths.AliasesFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if errors.Is(err, securestore.ErrCannotDecrypt) {
		fmt.Fprintf(os.Stderr, "warning: cannot decrypt the alias cache with the current master key; ignoring it\n")
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Aliases []Alias `json:"aliases"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Aliases, nil
}
