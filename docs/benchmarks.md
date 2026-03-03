# Latency Benchmarks

This document describes the latency benchmarks for the AI Anonymizing Proxy's
anonymization pipeline. These benchmarks measure per-gate costs and are
enforced in CI to prevent performance regressions.

## Benchmark Suite

The benchmarks are located in `internal/anonymizer/bench_test.go` and measure
each stage of the anonymization pipeline.

### Regex/Cache Benchmarks

| Benchmark | Description |
|-----------|-------------|
| `BenchmarkRegexPassEmail` | Pure regex pattern matching for a single email address. Baseline cost of PII detection with no anonymizer overhead. |
| `BenchmarkRegexPassMultiple` | Regex matching with three email addresses in one input string. |
| `BenchmarkAnonymizeCacheHit` | Token lookup for a previously anonymized value. Measures the fast path when PII has been seen before in the session. |
| `BenchmarkAnonymizeCacheMiss` | Full anonymization path: regex match, token generation, and cache write. Worst-case latency for new PII values. |
| `BenchmarkAnonymizeNoMatch` | Overhead when text contains no PII. Measures the passthrough baseline. |
| `BenchmarkAnonymizeMixedContent` | Realistic mixed content with some PII (email in longer text). Measures typical request handling. |
| `BenchmarkTokenGeneration` | Cost of generating a deterministic PII token (MD5-based, not cryptographic). |

### Streaming Benchmarks

| Benchmark | Description |
|-----------|-------------|
| `BenchmarkStreamingFlush` | SSE event processing with token replacement. Measures `StreamingDeanonymize` with a realistic `text_delta` payload containing one token. |
| `BenchmarkStreamingFlushNoTokens` | Streaming passthrough when the session has no tokens. Fast path for responses without PII restoration. |
| `BenchmarkStreamingFlushMultipleEvents` | Multiple SSE events in a single chunk with token replacement. Measures batched event processing. |

## CI Threshold Budgets

The CI pipeline enforces latency budgets based on a 500ms baseline (typical
acceptable overhead for an AI API request). Benchmarks that exceed their budget
fail the build.

| Category | Budget | Rationale |
|----------|--------|-----------|
| Regex/Cache/Token | < 2.5ms (2,500,000 ns) | 0.5% of 500ms baseline |
| Streaming | < 20ms (20,000,000 ns) | 4% of 500ms baseline |

### Threshold Mapping

```
BenchmarkRegexPass*          → regex/cache budget (< 2.5ms)
BenchmarkAnonymizeCache*     → regex/cache budget (< 2.5ms)
BenchmarkTokenGeneration     → regex/cache budget (< 2.5ms)
BenchmarkAnonymize*          → regex/cache budget (< 2.5ms)
BenchmarkStreaming*          → streaming budget (< 20ms)
```

## Baseline Numbers (CI Reference)

These numbers were captured on GitHub Actions `ubuntu-latest` runners (AMD EPYC
7763 64-Core processors). Local results will vary based on hardware.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| RegexPassEmail | 1,729 | 256 | 2 |
| RegexPassMultiple | 2,643 | 288 | 4 |
| AnonymizeCacheHit | 24,120 | 873 | 35 |
| AnonymizeCacheMiss | 25,359 | 1,375 | 42 |
| AnonymizeNoMatch | 43,353 | 1,600 | 27 |
| AnonymizeMixedContent | 122,592 | 3,875 | 36 |
| StreamingFlush | 24,227 | 38,303 | 58 |
| StreamingFlushNoTokens | 163 | 96 | 3 |
| StreamingFlushMultipleEvents | 35,402 | 39,482 | 90 |
| TokenGeneration | 738 | 160 | 9 |

All benchmarks are well under their respective budgets:
- Regex/cache operations: ~0.12ms worst case (budget: 2.5ms)
- Streaming operations: ~0.04ms worst case (budget: 20ms)

## Running Benchmarks Locally

### Quick Run

```bash
make benchmark
```

This runs all benchmarks with `-benchtime=3s -count=3` and writes results to
`.tmp/benchmark-latest.txt`.

### Manual Run

```bash
go test -run='^$' -bench=. -benchmem -benchtime=5s ./internal/anonymizer/...
```

Options:
- `-run='^$'` skips unit tests (runs only benchmarks)
- `-benchtime=5s` runs each benchmark for 5 seconds (default: 1s)
- `-benchmem` includes memory allocation statistics
- `-count=3` runs each benchmark 3 times for consistency

### Comparing Results

Use `benchstat` to compare benchmark runs:

```bash
# Install benchstat
go install golang.org/x/perf/cmd/benchstat@latest

# Run benchmarks before and after changes
make benchmark
mv .tmp/benchmark-latest.txt .tmp/benchmark-before.txt

# Make changes...

make benchmark
mv .tmp/benchmark-latest.txt .tmp/benchmark-after.txt

# Compare
benchstat .tmp/benchmark-before.txt .tmp/benchmark-after.txt
```

## Implementation Notes

- **Verbose logging disabled**: Benchmarks call `SetVerbose(false)` to suppress
  `[DEANON]` log lines that would otherwise flood output during streaming
  benchmarks.

- **In-memory cache**: Benchmarks use an in-memory cache (no bbolt persistence)
  to isolate measurement from disk I/O.

- **AI disabled**: Ollama/AI verification is disabled (`useAI=false`) for
  deterministic, repeatable results.

- **Session isolation**: Each benchmark uses a unique session ID to prevent
  cross-contamination between test runs.
