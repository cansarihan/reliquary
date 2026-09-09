package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.osv.dev"

type Target struct {
	Path    string
	Version string
}

func (t Target) Key() string {
	return t.Path + "@" + t.Version
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Vuln struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Aliases          []string        `json:"aliases"`
	Severity         []Severity      `json:"severity"`
	Affected         []Affected      `json:"affected"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

type Client interface {
	Query(ctx context.Context, targets []Target) (map[string][]Vuln, error)
}

type HTTPClient struct {
	baseURL string
	client  *http.Client
}

func New(client *http.Client) *HTTPClient {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &HTTPClient{baseURL: defaultBaseURL, client: client}
}

func (c *HTTPClient) Query(ctx context.Context, targets []Target) (map[string][]Vuln, error) {
	result := map[string][]Vuln{}
	if len(targets) == 0 {
		return result, nil
	}

	ids, err := c.batch(ctx, targets)
	if err != nil {
		return nil, err
	}

	cache := map[string]*Vuln{}
	for index, target := range targets {
		for _, id := range ids[index] {
			vuln, ok := cache[id]
			if !ok {
				fetched, err := c.vuln(ctx, id)
				if err != nil {
					continue
				}
				vuln = fetched
				cache[id] = vuln
			}
			result[target.Key()] = append(result[target.Key()], *vuln)
		}
	}
	return result, nil
}

func (c *HTTPClient) batch(ctx context.Context, targets []Target) ([][]string, error) {
	type query struct {
		Package Package `json:"package"`
		Version string  `json:"version,omitempty"`
	}
	body := struct {
		Queries []query `json:"queries"`
	}{}
	for _, target := range targets {
		body.Queries = append(body.Queries, query{
			Package: Package{Name: target.Path, Ecosystem: "Go"},
			Version: strings.TrimPrefix(target.Version, "v"),
		})
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/querybatch", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv querybatch: %s", response.Status)
	}

	var decoded struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	ids := make([][]string, len(targets))
	for index := range targets {
		if index >= len(decoded.Results) {
			break
		}
		for _, vuln := range decoded.Results[index].Vulns {
			ids[index] = append(ids[index], vuln.ID)
		}
	}
	return ids, nil
}

func (c *HTTPClient) vuln(ctx context.Context, id string) (*Vuln, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv vuln %s: %s", id, response.Status)
	}
	var vuln Vuln
	if err := json.NewDecoder(response.Body).Decode(&vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

func Vector(vuln Vuln) string {
	for _, severity := range vuln.Severity {
		if severity.Type == "CVSS_V3" {
			return severity.Score
		}
	}
	return ""
}

func CVE(vuln Vuln) string {
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return vuln.ID
}

func FixedVersion(vuln Vuln, path string) string {
	for _, affected := range vuln.Affected {
		if affected.Package.Name != path {
			continue
		}
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}
