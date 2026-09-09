package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cansarihan/reliquary/internal/engine"
	"github.com/cansarihan/reliquary/internal/module"
	"github.com/cansarihan/reliquary/internal/osv"
)

type BuildInfo struct {
	Version   string
	Commit    string
	GoVersion string
	Platform  string
}

type Options struct {
	Dir        string
	Token      string
	UI         bool
	Timeout    time.Duration
	MaxHistory int
	Client     osv.Client
}

type Server struct {
	options Options
	info    BuildInfo
	started time.Time

	mu    sync.Mutex
	scans []*scanState
}

type scanState struct {
	mu      sync.Mutex
	record  Scan
	modules map[string]*engine.ModuleReport
	order   []string
	feed    *feed
}

func New(options Options, info BuildInfo) *Server {
	if options.MaxHistory <= 0 {
		options.MaxHistory = 25
	}
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Second
	}
	return &Server{options: options, info: info, started: time.Now()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /api/v1/status", s.guard(s.handleStatus))
	mux.HandleFunc("GET /api/v1/scans", s.guard(s.handleList))
	mux.HandleFunc("POST /api/v1/scans", s.guard(s.handleCreate))
	mux.HandleFunc("GET /api/v1/scans/{id}", s.guard(s.handleGet))
	mux.HandleFunc("GET /api/v1/scans/{id}/stream", s.guard(s.handleStream))
	if s.options.UI {
		mux.Handle("GET /", uiHandler())
	}
	return mux
}

func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	token := s.options.Token
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if provided == "" {
				provided = r.URL.Query().Get("token")
			}
			if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	total := len(s.scans)
	running := 0
	for _, scan := range s.scans {
		if scan.snapshot().Status == "running" {
			running++
		}
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, Status{
		Version:   s.info.Version,
		Commit:    s.info.Commit,
		GoVersion: s.info.GoVersion,
		Platform:  s.info.Platform,
		Dir:       s.options.Dir,
		StartedAt: s.started,
		Uptime:    time.Since(s.started).Round(time.Second).String(),
		Scans:     total,
		Running:   running,
	})
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make([]Scan, 0, len(s.scans))
	for index := len(s.scans) - 1; index >= 0; index-- {
		out = append(out, s.scans[index].snapshot())
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	if state := s.find(r.PathValue("id")); state != nil {
		writeJSON(w, http.StatusOK, state.snapshot())
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	project, err := module.Parse(s.options.Dir)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	state := &scanState{
		modules: map[string]*engine.ModuleReport{},
		feed:    newFeed(8192),
		record: Scan{
			ID:      newID(),
			Main:    project.Main,
			Dir:     s.options.Dir,
			Status:  "running",
			Started: time.Now(),
			Total:   len(project.Modules),
			Counts:  map[string]int{},
		},
	}

	s.mu.Lock()
	s.scans = append(s.scans, state)
	if len(s.scans) > s.options.MaxHistory {
		s.scans = s.scans[len(s.scans)-s.options.MaxHistory:]
	}
	s.mu.Unlock()

	go s.execute(context.WithoutCancel(r.Context()), state, project)
	writeJSON(w, http.StatusAccepted, state.snapshot())
}

func (s *Server) execute(ctx context.Context, state *scanState, project module.Project) {
	client := s.options.Client
	if client == nil {
		client = osv.New(&http.Client{Timeout: s.options.Timeout})
	}
	summary, err := engine.Run(ctx, project, client, func(update engine.Update) {
		state.apply(update)
		if payload, marshalErr := json.Marshal(update); marshalErr == nil {
			state.feed.publish(payload)
		}
	})

	state.mu.Lock()
	state.record.Status = "done"
	state.record.Finished = time.Now()
	if err != nil {
		state.record.Error = err.Error()
	} else {
		state.record.Vulnerable = summary.Vulnerable
		state.record.Findings = summary.Findings
		state.record.Counts = summary.Counts
		state.record.Worst = summary.Worst
		state.record.Index = summary.Index
		state.record.Band = summary.Band
		state.record.Done = summary.Total
	}
	state.mu.Unlock()

	state.feed.publish([]byte(`{"type":"done"}`))
	state.feed.close()
}

func (state *scanState) apply(update engine.Update) {
	state.mu.Lock()
	defer state.mu.Unlock()

	switch update.Type {
	case engine.UpdateModule:
		if update.Module != nil {
			if _, ok := state.modules[update.Module.Path]; !ok {
				state.order = append(state.order, update.Module.Path)
			}
			state.modules[update.Module.Path] = update.Module
		}
	case engine.UpdateProgress:
		state.record.Done = update.Done
		if update.Total > 0 {
			state.record.Total = update.Total
		}
	}
}

func (state *scanState) snapshot() Scan {
	state.mu.Lock()
	defer state.mu.Unlock()

	record := state.record
	record.Modules = make([]engine.ModuleReport, 0, len(state.order))
	for _, path := range state.order {
		record.Modules = append(record.Modules, *state.modules[path])
	}
	return record
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	state := s.find(r.PathValue("id"))
	if state == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming is not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	events, unsubscribe, history := state.feed.subscribe()
	defer unsubscribe()

	for _, event := range history {
		writeEvent(w, event)
	}
	flusher.Flush()

	if r.URL.Query().Get("stream") == "off" {
		return
	}

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			writeEvent(w, event)
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = fmt.Fprint(w, ": keep alive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) find(id string) *scanState {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, state := range s.scans {
		if state.record.ID == id {
			return state
		}
	}
	return nil
}

type feed struct {
	limit   int
	mu      sync.Mutex
	history [][]byte
	subs    map[int]chan []byte
	seq     int
	closed  bool
}

func newFeed(limit int) *feed {
	return &feed{limit: limit, subs: map[int]chan []byte{}}
}

func (f *feed) publish(data []byte) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	if len(f.history) < f.limit {
		f.history = append(f.history, data)
	}
	targets := make([]chan []byte, 0, len(f.subs))
	for _, channel := range f.subs {
		targets = append(targets, channel)
	}
	f.mu.Unlock()

	for _, channel := range targets {
		select {
		case channel <- data:
		default:
		}
	}
}

func (f *feed) subscribe() (<-chan []byte, func(), [][]byte) {
	channel := make(chan []byte, 256)
	f.mu.Lock()
	history := append([][]byte(nil), f.history...)
	if f.closed {
		f.mu.Unlock()
		close(channel)
		return channel, func() {}, history
	}
	f.seq++
	id := f.seq
	f.subs[id] = channel
	f.mu.Unlock()

	return channel, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if existing, ok := f.subs[id]; ok {
			delete(f.subs, id)
			close(existing)
		}
	}, history
}

func (f *feed) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	for id, channel := range f.subs {
		delete(f.subs, id)
		close(channel)
	}
}

func writeEvent(w http.ResponseWriter, data []byte) {
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func newID() string {
	buffer := make([]byte, 5)
	_, _ = rand.Read(buffer)
	return hex.EncodeToString(buffer)
}
