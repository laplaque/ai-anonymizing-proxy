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
