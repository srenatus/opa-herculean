package engine

import (
	"fmt"
	"hash"
	"hash/fnv"
	"log"

	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/davecgh/go-spew/spew"
)

type memoized struct {
	cache    map[string]Findings
	delegate Engine
}

func NewMemoizedEngine(delegate Engine) (Engine, error) {
	return &memoized{
		cache:    make(map[string]Findings),
		delegate: delegate,
	}, nil
}

func (m *memoized) Eval(event types.Event) (Findings, error) {
	var e external.Event
	switch event.(type) {
	case ParsedEvent:
		e = (event.(ParsedEvent)).Event
	case external.Event:
		e = event.(external.Event)
	}

	cp := e
	cp.EventID = 0
	cp.Timestamp = 0
	eventHash := ComputeHash(cp)
	if findings, ok := m.cache[eventHash]; ok {
		var cfindings Findings
		copy(cfindings, findings)
		for _, f := range cfindings {
			f.Context = e
		}
		log.Printf("Cache of size (%d) hit for event hash %s \n", len(m.cache), eventHash)
		return findings, nil
	}

	findings, err := m.delegate.Eval(event)
	if err != nil {
		return nil, err
	}
	m.cache[eventHash] = findings
	return findings, nil
}

// ComputeHash returns a hash value calculated from a given object.
// The hash will be safe encoded to avoid bad words.
func ComputeHash(obj interface{}) string {
	hasher := fnv.New32a()
	DeepHashObject(hasher, obj)
	return fmt.Sprint(hasher.Sum32())
}

// DeepHashObject writes specified object to hash using the spew library
// which follows pointers and prints actual values of the nested objects
// ensuring the hash does not change when a pointer changes.
func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}
