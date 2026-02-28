package metrics

import (
	"testing"
	"time"
)

func TestNew_StartTimeSet(t *testing.T) {
	before := time.Now()
	m := New()
	after := time.Now()

	if m.startTime.Before(before) || m.startTime.After(after) {
		t.Errorf("startTime %v not in expected range [%v, %v]", m.startTime, before, after)
	}
}

func TestZeroValue_SnapshotSafe(t *testing.T) {
	var m Metrics
	s := m.Snapshot()
	if s.Requests.Total != 0 {
		t.Errorf("expected 0 total requests, got %d", s.Requests.Total)
	}
}

func TestRequestCounters(t *testing.T) {
	m := New()
	m.RequestsTotal.Add(10)
	m.RequestsAnonymized.Add(7)
	m.RequestsPassthrough.Add(2)
	m.RequestsAuth.Add(1)

	s := m.Snapshot()
	if s.Requests.Total != 10 {
		t.Errorf("Total: got %d, want 10", s.Requests.Total)
	}
	if s.Requests.Anonymized != 7 {
		t.Errorf("Anonymized: got %d, want 7", s.Requests.Anonymized)
	}
	if s.Requests.Passthrough != 2 {
		t.Errorf("Passthrough: got %d, want 2", s.Requests.Passthrough)
	}
	if s.Requests.Auth != 1 {
		t.Errorf("Auth: got %d, want 1", s.Requests.Auth)
	}
}

func TestErrorCounters(t *testing.T) {
	m := New()
	m.ErrorsUpstream.Add(3)
	m.ErrorsAnonymize.Add(2)

	s := m.Snapshot()
	if s.Errors.Upstream != 3 {
		t.Errorf("Upstream errors: got %d, want 3", s.Errors.Upstream)
	}
	if s.Errors.Anonymize != 2 {
		t.Errorf("Anonymize errors: got %d, want 2", s.Errors.Anonymize)
	}
}

func TestPIITokenCounters(t *testing.T) {
	m := New()
	m.TokensReplaced.Add(50)
	m.TokensDeanonymized.Add(45)

	s := m.Snapshot()
	if s.PIITokens.Replaced != 50 {
		t.Errorf("TokensReplaced: got %d, want 50", s.PIITokens.Replaced)
	}
	if s.PIITokens.Deanonymized != 45 {
		t.Errorf("TokensDeanonymized: got %d, want 45", s.PIITokens.Deanonymized)
	}
}

func TestRecordAnonLatency_SingleSample(t *testing.T) {
	m := New()
	m.RecordAnonLatency(100 * time.Millisecond)

	s := m.Snapshot()
	if s.Latency.AnonymizationMs.Count != 1 {
		t.Errorf("Count: got %d, want 1", s.Latency.AnonymizationMs.Count)
	}
	// 100ms should be recorded as ~100ms
	if s.Latency.AnonymizationMs.MinMs < 90 || s.Latency.AnonymizationMs.MinMs > 110 {
		t.Errorf("MinMs: got %f, want ~100", s.Latency.AnonymizationMs.MinMs)
	}
}

func TestRecordUpstreamLatency_MinMaxMean(t *testing.T) {
	m := New()
	m.RecordUpstreamLatency(50 * time.Millisecond)
	m.RecordUpstreamLatency(150 * time.Millisecond)
	m.RecordUpstreamLatency(100 * time.Millisecond)

	s := m.Snapshot()
	ls := s.Latency.UpstreamMs
	if ls.Count != 3 {
		t.Errorf("Count: got %d, want 3", ls.Count)
	}
	if ls.MinMs > 60 {
		t.Errorf("MinMs too high: %f", ls.MinMs)
	}
	if ls.MaxMs < 140 {
		t.Errorf("MaxMs too low: %f", ls.MaxMs)
	}
	// mean ~100ms
	if ls.MeanMs < 90 || ls.MeanMs > 110 {
		t.Errorf("MeanMs: got %f, want ~100", ls.MeanMs)
	}
}

func TestSnapshotLatency_EmptyIsZeroValue(t *testing.T) {
	m := New()
	s := m.Snapshot()
	if s.Latency.AnonymizationMs.Count != 0 {
		t.Errorf("empty anon latency count should be 0")
	}
	if s.Latency.UpstreamMs.Count != 0 {
		t.Errorf("empty upstream latency count should be 0")
	}
}

func TestSnapshot_UptimePositive(t *testing.T) {
	m := New()
	time.Sleep(5 * time.Millisecond)
	s := m.Snapshot()
	if s.UptimeSecs <= 0 {
		t.Errorf("UptimeSecs should be positive, got %f", s.UptimeSecs)
	}
}

func TestRound2(t *testing.T) {
	cases := []struct {
		input float64
		want  float64
	}{
		{1.236, 1.24},
		{1.234, 1.23},
		{100.0, 100.0},
		{0.0, 0.0},
	}
	for _, c := range cases {
		got := round2(c.input)
		if got != c.want {
			t.Errorf("round2(%f) = %f, want %f", c.input, got, c.want)
		}
	}
}

func TestLatencyStats_Record(t *testing.T) {
	var s latencyStats
	s.record(10)
	s.record(20)
	s.record(15)

	snap := s.snapshot()
	if snap.Count != 3 {
		t.Errorf("Count: got %d, want 3", snap.Count)
	}
	if snap.MinMs != 10 {
		t.Errorf("MinMs: got %f, want 10", snap.MinMs)
	}
	if snap.MaxMs != 20 {
		t.Errorf("MaxMs: got %f, want 20", snap.MaxMs)
	}
	if snap.MeanMs != 15 {
		t.Errorf("MeanMs: got %f, want 15", snap.MeanMs)
	}
}

func TestCacheHitCounters(t *testing.T) {
	m := New()
	m.RecordCacheHit("email")
	m.RecordCacheHit("email")
	m.RecordCacheHit("phone")

	s := m.Snapshot()
	if s.PIITokens.CacheHits["email"] != 2 {
		t.Errorf("email hits: got %d, want 2", s.PIITokens.CacheHits["email"])
	}
	if s.PIITokens.CacheHits["phone"] != 1 {
		t.Errorf("phone hits: got %d, want 1", s.PIITokens.CacheHits["phone"])
	}
	if _, present := s.PIITokens.CacheHits["ssn"]; present {
		t.Error("ssn should be absent from snapshot when count is 0")
	}
}

func TestCacheMissCounters(t *testing.T) {
	m := New()
	m.RecordCacheMiss("phone")
	m.RecordCacheMiss("phone")
	m.RecordCacheMiss("ipAddress")

	s := m.Snapshot()
	if s.PIITokens.CacheMisses["phone"] != 2 {
		t.Errorf("phone misses: got %d, want 2", s.PIITokens.CacheMisses["phone"])
	}
	if s.PIITokens.CacheMisses["ipAddress"] != 1 {
		t.Errorf("ipAddress misses: got %d, want 1", s.PIITokens.CacheMisses["ipAddress"])
	}
}

func TestCacheUnknownTypeIgnored(t *testing.T) {
	m := New()
	// Should not panic or create a new entry for an unknown type.
	m.RecordCacheHit("unknownType")
	m.RecordCacheMiss("unknownType")

	s := m.Snapshot()
	if _, present := s.PIITokens.CacheHits["unknownType"]; present {
		t.Error("unknown type should not appear in snapshot")
	}
}

func TestOllamaAndFallbackCounters(t *testing.T) {
	m := New()
	m.OllamaDispatches.Add(5)
	m.OllamaErrors.Add(2)
	m.CacheFallbacks.Add(3)

	s := m.Snapshot()
	if s.PIITokens.OllamaDispatches != 5 {
		t.Errorf("OllamaDispatches: got %d, want 5", s.PIITokens.OllamaDispatches)
	}
	if s.PIITokens.OllamaErrors != 2 {
		t.Errorf("OllamaErrors: got %d, want 2", s.PIITokens.OllamaErrors)
	}
	if s.PIITokens.CacheFallbacks != 3 {
		t.Errorf("CacheFallbacks: got %d, want 3", s.PIITokens.CacheFallbacks)
	}
}

func TestCacheCountersZeroValueOmitted(t *testing.T) {
	m := New()
	s := m.Snapshot()
	if len(s.PIITokens.CacheHits) != 0 {
		t.Errorf("CacheHits should be empty map when all zero, got %v", s.PIITokens.CacheHits)
	}
	if len(s.PIITokens.CacheMisses) != 0 {
		t.Errorf("CacheMisses should be empty map when all zero, got %v", s.PIITokens.CacheMisses)
	}
}

func TestLatencyStats_Empty(t *testing.T) {
	var s latencyStats
	snap := s.snapshot()
	if snap.Count != 0 || snap.MinMs != 0 || snap.MaxMs != 0 || snap.MeanMs != 0 {
		t.Errorf("empty stats snapshot should be zero, got %+v", snap)
	}
}
