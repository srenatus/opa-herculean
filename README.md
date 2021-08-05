# opa-herculean

## TOC

- [1. Compile and evaluate N queries vs compile and evaluate 1 query](#1-compile-and-evaluate-n-queries-vs-compile-and-evaluate-1-query)
  - [1.1 Run tests](#11-run-tests)
  - [1.2 Run benchmarks (6 signatures)](#12-run-benchmarks-6-signatures)
  - [1.3 Run benchmarks (71 signatures)](#13-run-benchmarks-71-signatures)

## 1. Compile and evaluate N queries vs compile and evaluate 1 query

To understand what is the difference between evaluating multiple Rego queries per signature
(`data.tracee.TRC_1.tracee_match`, `data.tracee.TRC_2.tracee_match`, ..., `data.tracee.TRC_N.tracee_match`) versus
evaluating one query (`data.main.tracee_match_all`) for the given input event.

```rego
package main

# Returns the map of signature identifiers to signature metadata.
__rego_metadoc_all__[id] = resp {
	some i
		resp := data.tracee[i].__rego_metadoc__
		id := resp.id
}

# Returns the map of signature identifiers to values matching the input event.
tracee_match_all[id] = resp {
	some i
		resp := data.tracee[i].tracee_match
		metadata := data.tracee[i].__rego_metadoc__
		id := metadata.id
}
````

### 1.1 Run tests

> **NOTE** Currently the unit tests only pass with signatures written by security research team, revision 036720606f448bb5d4f5891a79b9c7134d2f1467.

```
go test -v -run=Engine ./... \
  -enginerulesdir=/Users/dpacak/dev/my_rulez/rego \
  -enginehelpers=/Users/dpacak/dev/my_rulez/helpers.rego
=== RUN   TestEngine
--- PASS: TestEngine (0.14s)
=== RUN   TestAIOEngine
--- PASS: TestAIOEngine (0.05s)
PASS
ok  	github.com/danielpacak/opa-herculean/engine	1.410s
```

### 1.2 Run benchmarks (6 signatures)

```
go test -run=none -bench=BenchmarkEngine -benchmem -benchtime=3s ./... \
  -enginerulesdir=/Users/dpacak/dev/my_rulez/rego \
  -enginehelpers=/Users/dpacak/dev/my_rulez/helpers.rego
goos: darwin
goarch: amd64
pkg: github.com/danielpacak/opa-herculean/engine
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkEngine-16    	    8901	    371828 ns/op	  189061 B/op	    4211 allocs/op
PASS
ok  	github.com/danielpacak/opa-herculean/engine	4.778s
```

```
go test -run=none -bench=BenchmarkAIOEngine -benchmem -benchtime=3s ./... \
  -enginerulesdir=/Users/dpacak/dev/my_rulez/rego \
  -enginehelpers=/Users/dpacak/dev/my_rulez/helpers.rego
goos: darwin
goarch: amd64
pkg: github.com/danielpacak/opa-herculean/engine
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkAIOEngine-16    	   23830	    150952 ns/op	   73556 B/op	    1475 allocs/op
PASS
ok  	github.com/danielpacak/opa-herculean/engine	5.949s
```

### 1.3 Run benchmarks (71 signatures)

```
go test -run=none -bench=BenchmarkEngine -benchmem -benchtime=3s ./... \
  -enginerulesdir=/Users/dpacak/dev/my_rulez/rego \
  -enginehelpers=/Users/dpacak/dev/my_rulez/helpers.rego
goos: darwin
goarch: amd64
pkg: github.com/danielpacak/opa-herculean/engine
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkEngine-16    	     909	   3927822 ns/op	 2035393 B/op	   47008 allocs/op
PASS
ok  	github.com/danielpacak/opa-herculean/engine	5.137s
```

```
go test -run=none -bench=BenchmarkAIOEngine -benchmem -benchtime=3s ./... \
  -enginerulesdir=/Users/dpacak/dev/my_rulez/rego \
  -enginehelpers=/Users/dpacak/dev/my_rulez/helpers.rego
goos: darwin
goarch: amd64
pkg: github.com/danielpacak/opa-herculean/engine
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkAIOEngine-16    	    6608	    537862 ns/op	  246596 B/op	    5403 allocs/op
PASS
ok  	github.com/danielpacak/opa-herculean/engine	5.323s
```
