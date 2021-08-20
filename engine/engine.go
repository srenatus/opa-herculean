package engine

import (
	_ "embed"
	"encoding/json"
	"strconv"

	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/danielpacak/opa-herculean/mapper"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/util"
)

type Findings []types.Finding

type Engine interface {
	Eval(event types.Event) (Findings, error)
}

const (
	// ModuleNameHelpers the name of the Rego module with helper functions.
	ModuleNameHelpers = "helpers.rego"
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const (
	queryMetadata       = "data.%s.__rego_metadoc__"
	querySelectedEvents = "data.%s.tracee_selected_events"
	queryMatch          = "data.%s.tracee_match"
)

type engine struct {
	sigIDToPreparedQuery  map[string]rego.PreparedEvalQuery
	sigIDToMetadata       map[string]types.SignatureMetadata
	sigIDToSelectedEvents map[string][]types.SignatureEventSelector

	index index
}

// NewEngine constructs a new Engine with the specified Rego modules.
// This implementation compiles each module separately and prepares
// multiple queries for evaluation.
func NewEngine(modules map[string]string) (Engine, error) {
	sigIDToPreparedQuery := make(map[string]rego.PreparedEvalQuery)
	sigIDToMetadata := make(map[string]types.SignatureMetadata)
	sigIDToSelectedEvents := make(map[string][]types.SignatureEventSelector)

	ctx := context.TODO()
	for moduleName, code := range modules {
		if moduleName == ModuleNameHelpers {
			continue
		}
		compiler, err := ast.CompileModules(map[string]string{
			moduleName:        code,
			ModuleNameHelpers: modules[ModuleNameHelpers],
		})
		if err != nil {
			return nil, fmt.Errorf("compiling module: %s: %w", moduleName, err)
		}

		pkgName, err := GetPackageNameFromCode(code)
		if err != nil {
			return nil, fmt.Errorf("getting package name: %w", err)
		}

		metadataRS, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(fmt.Sprintf(queryMetadata, pkgName)),
		).Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("evaluating signature metadata: %w", err)
		}
		metadata, err := mapper.With(metadataRS).ToSignatureMetadata()
		if err != nil {
			return nil, err
		}
		sigIDToMetadata[metadata.ID] = metadata

		selectedEventsRS, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(fmt.Sprintf(querySelectedEvents, pkgName)),
		).Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("evaluating signature selected events: %w", err)
		}
		selectedEvents, err := mapper.With(selectedEventsRS).ToSelectedEvents()
		if err != nil {
			return nil, err
		}
		sigIDToSelectedEvents[metadata.ID] = selectedEvents

		peq, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(fmt.Sprintf(queryMatch, pkgName)),
		).PrepareForEval(ctx, rego.WithPartialEval())
		if err != nil {
			return nil, fmt.Errorf("preparing for evaluation: %s: %w", moduleName, err)
		}
		sigIDToPreparedQuery[metadata.ID] = peq
	}

	return &engine{
		sigIDToPreparedQuery:  sigIDToPreparedQuery,
		sigIDToMetadata:       sigIDToMetadata,
		sigIDToSelectedEvents: sigIDToSelectedEvents,

		index: newIndex(sigIDToSelectedEvents),
	}, nil
}

// Eval iterates through all queries prepared by the NewEngine constructor
// and evaluates the specified event.
func (e *engine) Eval(ee types.Event) (Findings, error) {
	input, event, err := toInputOption(ee)
	if err != nil {
		return nil, err
	}

	ctx := context.TODO()
	var findings []types.Finding

	for _, sigID := range e.index.getSignaturesMatchingEvent(event) {
		peq := e.sigIDToPreparedQuery[sigID]

		rs, err := peq.Eval(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("evaluating %s with input event %d: %w", sigID, event.EventID, err)
		}

		finding, err := mapper.With(rs).ToFinding(event, e.sigIDToMetadata[sigID])
		if err != nil {
			return nil, err
		}

		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const (
	moduleMain             = "main.rego"
	queryMetadataAll       = "data.main.__rego_metadoc_all__"
	querySelectedEventsAll = "data.main.tracee_selected_events_all"
	queryMatchAll          = "data.main.tracee_match_all"
)

var (
	//go:embed aio.rego
	mainRego string
)

type aio struct {
	preparedQuery         rego.PreparedEvalQuery
	sigIDToMetadata       map[string]types.SignatureMetadata
	sigIDToSelectedEvents map[string][]types.SignatureEventSelector

	index index
}

// NewAIOEngine constructs a new Engine with the specified Rego modules.
// This implementation compiles all modules once and prepares the single
// query for evaluation.
func NewAIOEngine(modules map[string]string) (Engine, error) {
	modules[moduleMain] = mainRego
	ctx := context.TODO()
	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("compiling modules: %w", err)
	}

	metadataRS, err := rego.New(
		rego.Compiler(compiler),
		rego.Query(queryMetadataAll),
	).Eval(ctx)
	if err != nil {
		return nil, err
	}
	sigIDToMetadata, err := mapper.With(metadataRS).ToSignatureMetadataAll()
	if err != nil {
		return nil, err
	}

	selectedEventsRS, err := rego.New(
		rego.Compiler(compiler),
		rego.Query(querySelectedEventsAll),
	).Eval(ctx)
	if err != nil {
		return nil, err
	}
	sigIDToSelectedEvents, err := mapper.With(selectedEventsRS).ToSelectedEventsAll()
	if err != nil {
		return nil, err
	}

	preparedQuery, err := rego.New(
		rego.Compiler(compiler),
		rego.Query(queryMatchAll),
	).PrepareForEval(ctx, rego.WithPartialEval())
	if err != nil {
		return nil, fmt.Errorf("preparing for eval: %w", err)
	}

	return &aio{
		preparedQuery:         preparedQuery,
		sigIDToMetadata:       sigIDToMetadata,
		sigIDToSelectedEvents: sigIDToSelectedEvents,

		index: newIndex(sigIDToSelectedEvents),
	}, nil
}

func (e *aio) Eval(ee types.Event) (Findings, error) {
	input, event, err := toInputOption(ee)
	if err != nil {
		return nil, err
	}

	if !(e.index.hasAnySignatureMatchingEventName(event) || e.index.hasAnySignatureMatchingAnyEventName()) {
		return Findings{}, nil
	}

	ctx := context.TODO()
	rs, err := e.preparedQuery.Eval(ctx, input)
	if err != nil {
		return nil, err
	}
	return e.findingsFrom(rs, event)
}

func (e *aio) findingsFrom(rs rego.ResultSet, event external.Event) (Findings, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil {
		return nil, errors.New("empty result set")
	}
	values, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unrecognized value: %T", rs[0].Expressions[0].Value)
	}
	var findings []types.Finding

	for signatureID, value := range values {
		finding, err := e.findingFrom(value, signatureID, event)
		if err != nil {
			return nil, err
		}
		if finding == nil {
			continue
		}

		findings = append(findings, *finding)
	}

	return findings, nil
}

func (e *aio) findingFrom(value interface{}, signatureID string, event external.Event) (*types.Finding, error) {
	switch v := value.(type) {
	case bool:
		if v {
			return &types.Finding{
				Data:        nil,
				Context:     event,
				SigMetadata: e.sigIDToMetadata[signatureID],
			}, nil
		} else {
			return nil, nil
		}
	case map[string]interface{}:
		return &types.Finding{
			Data:        v,
			Context:     event,
			SigMetadata: e.sigIDToMetadata[signatureID],
		}, nil
	default:
		return nil, fmt.Errorf("unrecognized value: %T", v)
	}
}

// ParsedEvent holds the original external.Event and its OPA ast.Value representation.
type ParsedEvent struct {
	Event external.Event
	Value ast.Value
}

// ToParsedEvent enhances tracee.Event with OPA ast.Value. This is mainly used
// for performance optimization to avoid parsing tracee.Event multiple times.
func ToParsedEvent(e external.Event) (ParsedEvent, error) {
	u, err := toUnstructured(e)
	if err != nil {
		return ParsedEvent{}, fmt.Errorf("unstructuring event: %w", err)
	}
	// TODO In OPA >= v0.30.0 we can try passing tracee.Event directly to get rid of ToUnstructured call.
	v, err := ast.InterfaceToValue(u)
	if err != nil {
		return ParsedEvent{}, fmt.Errorf("converting unstructured event to OPA ast.Value: %w", err)
	}
	return ParsedEvent{
		Event: e,
		Value: v,
	}, nil
}

func toInputOption(ee types.Event) (rego.EvalOption, external.Event, error) {
	var input rego.EvalOption
	var event external.Event

	switch ee.(type) {
	case external.Event:
		event = ee.(external.Event)
		input = rego.EvalInput(ee)
	case ParsedEvent:
		pe := ee.(ParsedEvent)
		event = pe.Event
		input = rego.EvalParsedInput(pe.Value)
	default:
		return nil, external.Event{}, fmt.Errorf("unrecognized event type: %T", ee)
	}
	return input, event, nil
}

var (
	packageNameRegex = regexp.MustCompile(`package\s.*`)
)

func GetPackageNameFromCode(code string) (string, error) {
	var pkgName string
	var regoModuleName string
	splittedName := strings.Split(packageNameRegex.FindString(code), " ")
	if len(splittedName) > 1 {
		regoModuleName = splittedName[1]
	} else {
		return "", fmt.Errorf("invalid rego code received")
	}
	if !strings.Contains(code, "package tracee.helpers") {
		pkgName = regoModuleName
	}
	return pkgName, nil
}

func GetModulesFromDir(dir string) (map[string]string, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error reading plugins directory %s: %v", dir, err)
	}

	modules := make(map[string]string)

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".rego" {
			continue
		}
		if file.Name() == ModuleNameHelpers {
			continue
		}
		regoCode, err := GetFileContentAsString(filepath.Join(dir, file.Name()))
		if err != nil {
			return nil, err
		}

		modules[file.Name()] = regoCode
	}
	return modules, nil
}

func GetFileContentAsString(filename string) (string, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func toUnstructured(e external.Event) (map[string]interface{}, error) {
	var argsRef interface{}

	if e.Args != nil {
		args := make([]interface{}, len(e.Args))
		for i, arg := range e.Args {
			v := arg.Value
			err := util.RoundTrip(&v)
			if err != nil {
				return nil, fmt.Errorf("marshalling arg %s with value %v: %w", arg.Name, arg.Value, err)
			}
			args[i] = map[string]interface{}{
				"name":  arg.Name,
				"type":  arg.Type,
				"value": v,
			}
		}
		argsRef = args
	}

	var stackAddressesRef interface{}
	if e.StackAddresses != nil {
		// stackAddresses can be ignored in the context of tracee-rules
		stackAddressesRef = make([]interface{}, len(e.StackAddresses))
	}

	return map[string]interface{}{
		"timestamp":           json.Number(strconv.Itoa(e.Timestamp)),
		"processId":           json.Number(strconv.Itoa(e.ProcessID)),
		"threadId":            json.Number(strconv.Itoa(e.ThreadID)),
		"parentProcessId":     json.Number(strconv.Itoa(e.ParentProcessID)),
		"hostProcessId":       json.Number(strconv.Itoa(e.HostProcessID)),
		"hostThreadId":        json.Number(strconv.Itoa(e.HostThreadID)),
		"hostParentProcessId": json.Number(strconv.Itoa(e.HostParentProcessID)),
		"userId":              json.Number(strconv.Itoa(e.UserID)),
		"mountNamespace":      json.Number(strconv.Itoa(e.MountNS)),
		"pidNamespace":        json.Number(strconv.Itoa(e.PIDNS)),
		"processName":         e.ProcessName,
		"hostName":            e.HostName,
		"containerId":         e.ContainerID,
		"eventId":             strconv.Itoa(e.EventID),
		"eventName":           e.EventName,
		"argsNum":             json.Number(strconv.Itoa(e.ArgsNum)),
		"returnValue":         json.Number(strconv.Itoa(e.ReturnValue)),
		"args":                argsRef,
		"stackAddresses":      stackAddressesRef,
	}, nil
}
