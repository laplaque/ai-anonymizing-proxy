// Package metrics provides lightweight, lock-minimal performance counters
// for the AI anonymizing proxy.
//
// Counters use sync/atomic so hot paths (request handling, token replacement)
// incur no mutex contention. Latency statistics use a single mutex per
// dimension; they are updated at most once per request.
package metrics

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds all runtime counters for a running proxy instance.
// The zero value is valid and ready to use; prefer New() for clarity.
type Metrics struct {
	// Request counters
	RequestsTotal       atomic.Int64
	RequestsAnonymized  atomic.Int64
	RequestsPassthrough atomic.Int64
	RequestsAuth        atomic.Int64

	// Error counters
	ErrorsUpstream  atomic.Int64
	ErrorsAnonymize atomic.Int64

	// PII token volume
	TokensReplaced     atomic.Int64
	TokensDeanonymized atomic.Int64

	// Latency statistics (mutex-guarded because they accumulate floats)
	anonMu   sync.Mutex
	anonStat latencyStats

	upstreamMu   sync.Mutex
	upstreamStat latencyStats

	startTime time.Time
}

// New returns a new Metrics with the start time recorded.
func New() *Metrics {
	return &Metrics{startTime: time.Now()}
}

// RecordAnonLatency records the duration of one anonymization pass.
func (m *Metrics) RecordAnonLatency(d time.Duration) {
	m.anonMu.Lock()
	m.anonStat.record(float64(d.Microseconds()) / 1000.0)
	m.anonMu.Unlock()
}

// RecordUpstreamLatency records the round-trip time to the upstream AI API.
func (m *Metrics) RecordUpstreamLatency(d time.Duration) {
	m.upstreamMu.Lock()
	m.upstreamStat.record(float64(d.Microseconds()) / 1000.0)
	m.upstreamMu.Unlock()
}

// Snapshot returns a point-in-time copy of all metrics, safe for JSON encoding.
func (m *Metrics) Snapshot() Snapshot {
	m.anonMu.Lock()
	anon := m.anonStat.snapshot()
	m.anonMu.Unlock()

	m.upstreamMu.Lock()
	upstream := m.upstreamStat.snapshot()
	m.upstreamMu.Unlock()

	return Snapshot{
		Requests: RequestSnapshot{
			Total:       m.RequestsTotal.Load(),
			Anonymized:  m.RequestsAnonymized.Load(),
			Passthrough: m.RequestsPassthrough.Load(),
			Auth:        m.RequestsAuth.Load(),
		},
		Errors: ErrorSnapshot{
			Upstream:  m.ErrorsUpstream.Load(),
			Anonymize: m.ErrorsAnonymize.Load(),
		},
		PIITokens: PIISnapshot{
			Replaced:     m.TokensReplaced.Load(),
			Deanonymized: m.TokensDeanonymized.Load(),
		},
		Latency: LatencyGroup{
			AnonymizationMs: anon,
			UpstreamMs:      upstream,
		},
		UptimeSecs: time.Since(m.startTime).Seconds(),
	}
}

// --- JSON-serialisable snapshot types ---

// Snapshot is a point-in-time view of all metrics.
type Snapshot struct {
	Requests   RequestSnapshot `json:"requests"`
	Errors     ErrorSnapshot   `json:"errors"`
	PIITokens  PIISnapshot     `json:"piiTokens"`
	Latency    LatencyGroup    `json:"latency"`
	UptimeSecs float64         `json:"uptimeSecs"`
}

// RequestSnapshot holds request-level counters.
type RequestSnapshot struct {
	Total       int64 `json:"total"`
	Anonymized  int64 `json:"anonymized"`
	Passthrough int64 `json:"passthrough"`
	Auth        int64 `json:"auth"`
}

// ErrorSnapshot holds error counters.
type ErrorSnapshot struct {
	Upstream  int64 `json:"upstream"`
	Anonymize int64 `json:"anonymize"`
}

// PIISnapshot holds PII token volume counters.
type PIISnapshot struct {
	Replaced     int64 `json:"replaced"`
	Deanonymized int64 `json:"deanonymized"`
}

// LatencyGroup groups the two latency dimensions.
type LatencyGroup struct {
	AnonymizationMs LatencySnapshot `json:"anonymizationMs"`
	UpstreamMs      LatencySnapshot `json:"upstreamMs"`
}

// LatencySnapshot is a min/mean/max summary for one latency dimension.
type LatencySnapshot struct {
	Count  int64   `json:"count"`
	MinMs  float64 `json:"minMs"`
	MeanMs float64 `json:"meanMs"`
	MaxMs  float64 `json:"maxMs"`
}

// --- internal accumulator ---

type latencyStats struct {
	count int64
	sum   float64
	min   float64
	max   float64
}

func (s *latencyStats) record(ms float64) {
	s.count++
	s.sum += ms
	if s.count == 1 || ms < s.min {
		s.min = ms
	}
	if ms > s.max {
		s.max = ms
	}
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func (s *latencyStats) snapshot() LatencySnapshot {
	if s.count == 0 {
		return LatencySnapshot{}
	}
	return LatencySnapshot{
		Count:  s.count,
		MinMs:  round2(s.min),
		MeanMs: round2(s.sum / float64(s.count)),
		MaxMs:  round2(s.max),
	}
}
