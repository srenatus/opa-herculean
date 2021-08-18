package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/danielpacak/opa-herculean/engine"
)

var (
	engineImpl  string
	modulesDir  string
	helpersFile string
	input       string
)

// main is the entrypoint of the engine CLI.
//
//    ./engine --engine=aio \
//      --modules=/Users/dpacak/dev/my_rulez/rego \
//      --helpers=/Users/dpacak/dev/my_rulez/helpers.rego \
//      --input=stdio
func main() {
	flag.StringVar(&engineImpl, "engine", "aio", "The engine implementation [default|aio]")
	flag.StringVar(&modulesDir, "modules", "", "The absolute path to OPA signatures directory")
	flag.StringVar(&helpersFile, "helpers", "", "The absolute path to OPA helpers file")
	flag.StringVar(&input, "input", "stdio", "The input source [stdio|simple]")
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	modules, err := engine.GetModulesFromDir(modulesDir)
	if err != nil {
		return err
	}
	helpers, err := engine.GetFileContentAsString(helpersFile)
	if err != nil {
		return err
	}
	modules[engine.ModuleNameHelpers] = helpers
	var eng engine.Engine
	switch engineImpl {
	case "aio":
		log.Printf("Using %s engine\n", engineImpl)
		eng, err = engine.NewAIOEngine(modules)
		if err != nil {
			return err
		}
	case "default":
		log.Printf("Using %s engine\n", engineImpl)
		eng, err = engine.NewEngine(modules)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unrecognized engine: %s", engineImpl)
	}

	var eventsCh chan external.Event
	switch input {
	case "stdio":
		log.Printf("Using %s input\n", input)
		eventsCh, err = NewInput(os.Stdin)
		if err != nil {
			return err
		}
	case "simple":
		log.Printf("Using %s input\n", input)
		eventsCh, err = NewSimpleInput()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unrecognized input source: %s", input)
	}
	return process(eng, eventsCh, sigHandler())
}

// Done channel should be passed to gorutine that produces events
// Otherwise we may not print all detections due to signal interrupt.
func process(engine engine.Engine, eventsCh chan external.Event, done <-chan bool) error {

	for {
		select {
		case event, ok := <-eventsCh:
			if !ok {
				return nil
			}
			log.Printf("Processing event %s\n", event.EventName)
			findings, err := engine.Eval(event)
			if err != nil {
				fmt.Printf("error processing event %d: %v\n", event.EventID, err)
				continue
			}
			for _, f := range findings {
				log.Printf("Detection: %v\n", f.SigMetadata.Name)
			}
		case <-done:
			return nil
		}
	}
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
