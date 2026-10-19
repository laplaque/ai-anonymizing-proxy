package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"sync"
	"testing"
	"time"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	metricspkg "ai-anonymizing-proxy/internal/metrics"
)

// Resource measurements for full-context requests (issue #152). They run only
// with -bench and are meant to be run one scenario per process so peak RSS
// is attributable, e.g.:
//
//	go test -run '^$' -bench 'BenchmarkFullContext/size=64MiB/packs=global$' -benchtime 1x ./internal/proxy/
//
// Reported metrics:
//
//	MB/s               request bytes processed per second (end to end)
//	peak-rss-MiB       peak resident set during the request, above the pre-request RSS
//	peak-heap-MiB      peak Go heap object bytes during the request
//	body-MiB           raw request size
//
// The benchmark deliberately uses only APIs that also exist before #152, so
// the same file measures the previous implementation for comparison.

// memSampler records peak RSS and heap while a request runs.
type memSampler struct {
	stop     chan struct{}
	done     sync.WaitGroup
	baseRSS  int64
	peakRSS  int64
	peakHeap uint64
}

func readRSS() int64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := bytes.Fields(b)
	if len(fields) < 2 {
		return 0
	}
	pages, _ := strconv.ParseInt(string(fields[1]), 10, 64)
	return pages * int64(os.Getpagesize())
}

func startMemSampler() *memSampler {
	runtime.GC()
	s := &memSampler{stop: make(chan struct{}), baseRSS: readRSS()}
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			if rss := readRSS(); rss > s.peakRSS {
				s.peakRSS = rss
			}
			metrics.Read(sample)
			if h := sample[0].Value.Uint64(); h > s.peakHeap {
				s.peakHeap = h
			}
			select {
			case <-s.stop:
				return
			case <-tick.C:
			}
		}
	}()
	return s
}

func (s *memSampler) finish(b *testing.B) {
	close(s.stop)
	s.done.Wait()
	const mib = 1 << 20
	b.ReportMetric(float64(s.peakRSS-s.baseRSS)/mib, "peak-rss-MiB")
	b.ReportMetric(float64(s.peakHeap)/mib, "peak-heap-MiB")
}

func benchProxy(b *testing.B, packs []string) (*Server, *httptest.Server) {
	cfg := &config.Config{
		OllamaEndpoint:  "http://localhost:11434",
		OllamaModel:     "test",
		AIAPIDomains:    []string{"localhost"},
		AuthDomains:     []string{},
		AuthPaths:       []string{},
		EnabledPacks:    packs,
		PIIInstructions: map[string]string{"default": fullContextInstruction},
	}
	srv := New(cfg, management.NewDomainRegistry(cfg, ""), metricspkg.New())
	srv.anon.SetVerbose(false)
	srv.dialContext = (&localDialer).DialContext
	srv.transport.DialContext = (&localDialer).DialContext
	b.Cleanup(func() { _ = srv.Close() })
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	b.Cleanup(up.Close)
	return srv, up
}

// workloadOfSize returns a workload of roughly sizeMiB: half inline images
// (8 MiB of base64 each) above 16 MiB, the rest prose and tool history.
func workloadOfSize(sizeMiB int) fullContextWorkload {
	wl := fullContextWorkload{proseBytes: 20 << 10, instruction: fullContextInstruction}
	textMiB := sizeMiB
	if sizeMiB > 16 {
		wl.images = sizeMiB / 2 / 8
		wl.imageBytes = 6 << 20 // 8 MiB base64
		textMiB = sizeMiB - wl.images*8
	}
	wl.turns = textMiB << 20 / (wl.proseBytes + 700)
	return wl
}

var benchPackSets = map[string][]string{
	"global":  {"GLOBAL"},
	"default": {"SECRETS", "GLOBAL", "DE"},
}

func BenchmarkFullContext(b *testing.B) {
	for _, sizeMiB := range []int{4, 16, 40, 64, 128, 256} {
		for _, packName := range []string{"global", "default"} {
			b.Run(fmt.Sprintf("size=%dMiB/packs=%s", sizeMiB, packName), func(b *testing.B) {
				wl := workloadOfSize(sizeMiB)
				raw, _, err := wl.digests()
				if err != nil {
					b.Fatal(err)
				}
				srv, up := benchProxy(b, benchPackSets[packName])
				host := backendHostPort(&testing.T{}, up.URL, "http")
				b.SetBytes(raw.n)
				b.ResetTimer()
				for range b.N {
					sampler := startMemSampler()
					req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
						"http://"+host+"/v1/chat/completions", wl.rawStream())
					req.Host, req.URL.Host, req.ContentLength = host, host, raw.n
					req.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					srv.ServeHTTP(w, req)
					sampler.finish(b)
					if w.Code != http.StatusOK {
						b.Fatalf("status %d: %s", w.Code, w.Body.String())
					}
				}
				b.ReportMetric(float64(raw.n)/(1<<20), "body-MiB")
			})
		}
	}
}

// BenchmarkFullContextSingleString measures requests dominated by one JSON
// string value of sizeMiB, the case that bounds per-request memory: "prose"
// is one text string with a synthetic email every ~2 KiB (every pattern pass
// that matches copies the string), "base64" is one inline image data URL
// (no matches).
func BenchmarkFullContextSingleString(b *testing.B) {
	for _, sizeMiB := range []int{16, 64, 128} {
		for _, kind := range []string{"prose", "base64"} {
			b.Run(fmt.Sprintf("size=%dMiB/kind=%s/packs=global", sizeMiB, kind), func(b *testing.B) {
				wl := fullContextWorkload{turns: 1, proseBytes: sizeMiB << 20, instruction: fullContextInstruction}
				if kind == "base64" {
					wl.proseBytes = 1 << 10
					wl.images = 1
					wl.imageBytes = sizeMiB << 20 / 4 * 3
				}
				raw, _, err := wl.digests()
				if err != nil {
					b.Fatal(err)
				}
				srv, up := benchProxy(b, benchPackSets["global"])
				host := backendHostPort(&testing.T{}, up.URL, "http")
				b.SetBytes(raw.n)
				b.ResetTimer()
				for range b.N {
					sampler := startMemSampler()
					req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
						"http://"+host+"/v1/chat/completions", wl.rawStream())
					req.Host, req.URL.Host, req.ContentLength = host, host, raw.n
					req.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					srv.ServeHTTP(w, req)
					sampler.finish(b)
					if w.Code != http.StatusOK {
						b.Fatalf("status %d: %s", w.Code, w.Body.String())
					}
				}
				b.ReportMetric(float64(raw.n)/(1<<20), "body-MiB")
			})
		}
	}
}

// BenchmarkFullContextConcurrent measures n simultaneous requests of sizeMiB.
func BenchmarkFullContextConcurrent(b *testing.B) {
	for _, sc := range []struct{ n, sizeMiB int }{{4, 16}, {8, 16}, {4, 64}} {
		b.Run(fmt.Sprintf("n=%d/size=%dMiB/packs=global", sc.n, sc.sizeMiB), func(b *testing.B) {
			wl := workloadOfSize(sc.sizeMiB)
			raw, _, err := wl.digests()
			if err != nil {
				b.Fatal(err)
			}
			srv, up := benchProxy(b, benchPackSets["global"])
			host := backendHostPort(&testing.T{}, up.URL, "http")
			b.SetBytes(raw.n * int64(sc.n))
			b.ResetTimer()
			for range b.N {
				sampler := startMemSampler()
				var wg sync.WaitGroup
				codes := make([]int, sc.n)
				for i := range sc.n {
					wg.Add(1)
					go func() {
						defer wg.Done()
						req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
							"http://"+host+"/v1/chat/completions", wl.rawStream())
						req.Host, req.URL.Host, req.ContentLength = host, host, raw.n
						req.Header.Set("Content-Type", "application/json")
						w := httptest.NewRecorder()
						srv.ServeHTTP(w, req)
						codes[i] = w.Code
					}()
				}
				wg.Wait()
				sampler.finish(b)
				for i, c := range codes {
					if c != http.StatusOK {
						b.Fatalf("request %d: status %d", i, c)
					}
				}
			}
			b.ReportMetric(float64(raw.n)/(1<<20), "body-MiB")
		})
	}
}

// highCardinalityBody returns a chat request whose prose carries n distinct
// synthetic addresses, 50 per message.
func highCardinalityBody(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"model":"gpt-x","messages":[`)
	for i := 0; i < n; i += 50 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"role":"user","content":"`)
		for j := i; j < min(i+50, n); j++ {
			fmt.Fprintf(&b, "contact u%07d@example.com now. ", j)
		}
		b.WriteString(`"}`)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

// BenchmarkFullContextHighCardinality measures the memory term that grows
// with the number of distinct detected values rather than with the largest
// string: each value and its token stay in the request's session map until
// the response has been de-anonymized, however long that response takes.
// conc requests run at once, as conc long-lived responses would hold them.
//
//	retained-MiB       heap still held by the session maps after the bodies
//	                   were anonymized and their spools released (after GC)
//	retained-B/value   retained-MiB per distinct value
func BenchmarkFullContextHighCardinality(b *testing.B) {
	for _, sc := range []struct{ conc, values int }{
		{1, 10_000}, {1, 100_000}, {1, 1_000_000}, {4, 100_000}, {4, 1_000_000},
	} {
		b.Run(fmt.Sprintf("n=%d/values=%d/packs=global", sc.conc, sc.values), func(b *testing.B) {
			body := highCardinalityBody(sc.values)
			srv, _ := benchProxy(b, benchPackSets["global"])
			b.SetBytes(int64(len(body) * sc.conc))
			b.ResetTimer()
			for range b.N {
				runtime.GC()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)
				sampler := startMemSampler()
				sessions := make([]string, sc.conc)
				errs := make([]error, sc.conc)
				var wg sync.WaitGroup
				for i := range sc.conc {
					wg.Go(func() {
						req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
							"http://localhost/v1/chat/completions", bytes.NewReader(body))
						req.ContentLength = int64(len(body))
						req.Header.Set("Content-Type", "application/json")
						sid, release, err := srv.anonymizeRequestBody(req)
						if err == nil {
							release() // keep only what outlives the upload: the session map
						}
						sessions[i], errs[i] = sid, err
					})
				}
				wg.Wait()
				sampler.finish(b)
				for i, err := range errs {
					if err != nil {
						b.Fatalf("request %d: %v", i, err)
					}
					if n := srv.anon.SessionTokenCount(sessions[i]); n != sc.values {
						b.Fatalf("request %d recorded %d tokens, want %d", i, n, sc.values)
					}
				}
				runtime.GC()
				var held runtime.MemStats
				runtime.ReadMemStats(&held)
				retained := float64(held.HeapAlloc) - float64(before.HeapAlloc)
				b.ReportMetric(retained/(1<<20), "retained-MiB")
				b.ReportMetric(retained/float64(sc.values*sc.conc), "retained-B/value")
				for _, sid := range sessions {
					srv.anon.DeleteSession(sid)
				}
			}
			b.ReportMetric(float64(len(body))/(1<<20), "body-MiB")
		})
	}
}

// envelopeLimit is the per-request cap of the documented reference envelope
// (docs/configuration.md): 4 concurrent requests in 4 GiB of proxy memory.
const envelopeLimit = 112 << 20

// BenchmarkFullContextEnvelope runs the reference envelope's worst cases:
// four concurrent requests of about envelopeLimit bytes each, all of the same
// shape: one prose string with PII (the largest-string term), a mixed
// full-context request with tool history and inline images, or prose dense
// with distinct addresses (the session-map term). The proxy runs with
// maxRequestBodyBytes = envelopeLimit, so every request must pass the cap
// and complete.
func BenchmarkFullContextEnvelope(b *testing.B) {
	const conc = 4
	shapes := map[string]func() (io.Reader, int64){
		"single-prose-string": func() (io.Reader, int64) {
			wl := fullContextWorkload{turns: 1, proseBytes: envelopeLimit * 97 / 100, instruction: fullContextInstruction}
			raw, _, _ := wl.digests()
			return wl.rawStream(), raw.n
		},
		"mixed-full-context": func() (io.Reader, int64) {
			wl := workloadOfSize(envelopeLimit>>20 - 8)
			raw, _, _ := wl.digests()
			return wl.rawStream(), raw.n
		},
		"dense-distinct-pii": func() (io.Reader, int64) {
			body := highCardinalityBody(envelopeLimit / 35)
			return bytes.NewReader(body), int64(len(body))
		},
	}
	for _, name := range []string{"single-prose-string", "mixed-full-context", "dense-distinct-pii"} {
		b.Run(fmt.Sprintf("n=%d/shape=%s/limit=%dMiB/packs=global", conc, name, envelopeLimit>>20), func(b *testing.B) {
			srv, up := benchProxy(b, benchPackSets["global"])
			srv.cfg.MaxRequestBodyBytes = envelopeLimit
			host := backendHostPort(&testing.T{}, up.URL, "http")
			_, size := shapes[name]()
			if size > envelopeLimit {
				b.Fatalf("%s request is %d bytes, above the %d-byte cap", name, size, envelopeLimit)
			}
			b.SetBytes(size * conc)
			b.ResetTimer()
			for range b.N {
				sampler := startMemSampler()
				codes := make([]int, conc)
				var wg sync.WaitGroup
				for i := range conc {
					wg.Go(func() {
						body, n := shapes[name]()
						req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
							"http://"+host+"/v1/chat/completions", body)
						req.Host, req.URL.Host, req.ContentLength = host, host, n
						req.Header.Set("Content-Type", "application/json")
						w := httptest.NewRecorder()
						srv.ServeHTTP(w, req)
						codes[i] = w.Code
					})
				}
				wg.Wait()
				sampler.finish(b)
				for i, c := range codes {
					if c != http.StatusOK {
						b.Fatalf("request %d: status %d", i, c)
					}
				}
			}
			b.ReportMetric(float64(size)/(1<<20), "body-MiB")
		})
	}
}
