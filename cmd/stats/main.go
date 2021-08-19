package main

import (
	"encoding/gob"
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/danielpacak/opa-herculean/engine"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	eventsCh, err := NewInput(os.Stdin)
	done := sigHandler()
	if err != nil {
		return err
	}

	count := 0
	hashes := make(map[string]bool)

	for {
		select {
		case event, ok := <-eventsCh:
			if !ok {
				log.Printf("count: %d\n", count)
				log.Printf("hashes: %d\n", len(hashes))
				return nil
			}
			eventHash1 := engine.ComputeHash(event)
			event.EventID = 0
			event.Timestamp = 0
			eventHash2 := engine.ComputeHash(event)
			fmt.Printf("[%s,\t%s]\t%s\n", eventHash1, eventHash2, event.EventName)
			count = count + 1
			hashes[eventHash2] = true
		case <-done:
			log.Printf("count: %d\n", count)
			log.Printf("hashes: %d\n", len(hashes))
			return nil
		}
	}
}

func NewSimpleInput() (chan external.Event, error) {
	res := make(chan external.Event, 256)
	res <- external.Event{
		Timestamp:           5323321532,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     3788,
		HostProcessID:       3217,
		HostThreadID:        3217,
		HostParentProcessID: 3788,
		UserID:              0,
		MountNS:             2983424533,
		PIDNS:               2983424536,
		ProcessName:         "malware",
		HostName:            "234134134ab",
		EventID:             521,
		EventName:           "ptrace",
		ArgsNum:             2,
		ReturnValue:         124,
		Args: []external.Argument{
			{
				ArgMeta: external.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_TRACEME",
			},
		},
	}
	res <- external.Event{
		Timestamp:           6123321183,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     3788,
		HostProcessID:       3217,
		HostThreadID:        3217,
		HostParentProcessID: 3788,
		UserID:              0,
		MountNS:             2983424533,
		PIDNS:               2983424536,
		ProcessName:         "injector",
		HostName:            "234134134ab",
		EventID:             328,
		EventName:           "security_file_open",
		ArgsNum:             2,
		ReturnValue:         0,
		Args: []external.Argument{
			{
				ArgMeta: external.ArgMeta{
					Name: "pathname",
				},
				Value: "/proc/20/mem",
			},
			{
				ArgMeta: external.ArgMeta{
					Name: "flags",
				},
				Value: "o_rdwr",
			},
		},
	}
	close(res)
	return res, nil
}

func NewInput(in *os.File) (chan external.Event, error) {
	dec := gob.NewDecoder(in)
	gob.Register(external.Event{})
	gob.Register(external.SlimCred{})
	res := make(chan external.Event, 256)
	go func() {
		for {
			var event external.Event
			err := dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					log.Printf("Error while decoding event: %v", err)
				}
			} else {
				res <- event
			}
		}
		in.Close()
		close(res)
	}()
	return res, nil
}

func sigHandler() chan bool {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()
	return done
}
