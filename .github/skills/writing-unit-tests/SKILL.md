---
name: writing-unit-tests
description: Use when writing or reviewing Go unit tests to ensure consistent table-driven style, proper helper extraction, and no branching in test loops
---

# Writing Unit Tests in Go

## Table-Driven Tests

Table-driven tests are the default for unit tests. They excel at testing **simple permutations** of input/output through a single code path.

### Structure

```go
func TestParseConfig(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected Config
    }{
        {
            name:     "minimal config",
            input:    `{"port": 8080}`,
            expected: Config{Port: 8080},
        },
        {
            name:     "full config",
            input:    `{"port": 9090, "host": "localhost"}`,
            expected: Config{Port: 9090, Host: "localhost"},
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseConfig(tt.input)
            require.NoError(t, err)
            assert.Equal(t, tt.expected, got)
        })
    }
}
```

## Helpers: Extract Complexity

Complex setup does not belong inline. Extract it into named helpers.

### Fakes for Service-Layer Tests

When testing business logic that depends on interfaces (ports), define simple fakes in `_test.go` files:

```go
type fakeStore struct {
    entries   []domain.Entry
    loadErr   error
    updateErr error
    updated   []domain.Entry
}

func (s *fakeStore) LoadEntries(ctx context.Context, ...) ([]service.LoadedEntry, error) {
    if s.loadErr != nil {
        return nil, s.loadErr
    }
    // return pre-configured data
}
```

## One Test Function Per Function Under Test

All unit tests for a given function belong in a single `TestXxx` function, sharing one table. Don't split a function's test cases across multiple `TestXxx` functions (e.g. `TestParseConfig_Valid`, `TestParseConfig_Errors`) — consolidate them into one `TestParseConfig` with more rows in the table instead.

This means the test struct may need more fields as new scenarios are added (e.g. an `expectedErr` field alongside `expected`). That's fine — let the table grow to accommodate real permutations. Only split fields out or reach for a different structure if it grows past a reasonable size (as a rough guide, ~10+ fields is a signal the struct is doing too much and needs to be broken up, e.g. by extracting a options-pattern helper for setup instead of adding more fields).

```go
func TestParseConfig(t *testing.T) {
    tests := []struct {
        name        string
        input       string
        expected    Config
        expectedErr string
    }{
        {
            name:     "minimal config",
            input:    `{"port": 8080}`,
            expected: Config{Port: 8080},
        },
        {
            name:        "invalid port",
            input:       `{"port": "abc"}`,
            expectedErr: "invalid port",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseConfig(tt.input)
            if tt.expectedErr != "" {
                require.ErrorContains(t, err, tt.expectedErr)
                return
            }
            require.NoError(t, err)
            assert.Equal(t, tt.expected, got)
        })
    }
}
```

## Anti-Patterns

| Don't | Do instead |
|-------|-----------|
| Inline 20-line setup closures in test case structs | Extract to named helper functions |
| Construct raw domain objects with 15 fields in every test case | Use the options pattern with sensible defaults |
| Splitting one function's tests across multiple `TestXxx` functions | Consolidate into a single `TestXxx` with all scenarios in one table |
