# opa-herculean

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

```
git clone git@github.com:danielpacak/opa-herculean.git
cd opa-herculean
```

## Run tests

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

## Run benchmarks

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
