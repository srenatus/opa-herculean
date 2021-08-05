package engine_test

import (
	_ "embed"

	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/danielpacak/opa-herculean/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	rulesDir        string
	helpersFilename string
)

var (
	innocentEvent = external.Event{
		Timestamp:           7126141189,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     4798,
		HostProcessID:       4819,
		HostThreadID:        4819,
		HostParentProcessID: 4798,
		UserID:              0,
		MountNS:             4026532256,
		PIDNS:               4026532259,
		ProcessName:         "cadvisor",
		HostName:            "4213291591ab",
		EventID:             257,
		EventName:           "openat",
		ArgsNum:             4,
		ReturnValue:         14,
		Args: []external.Argument{
			{
				ArgMeta: external.ArgMeta{
					Name: "dirfd",
					Type: "int",
				},
				Value: -100,
			},
			{
				ArgMeta: external.ArgMeta{
					Name: "pathname",
					Type: "const char",
				},
				Value: "/sys/fs/cgroup/cpu,cpuacct/cpuacct.stat",
			},
			{
				ArgMeta: external.ArgMeta{
					Name: "flags",
					Type: "int",
				},
				Value: "O_RDONLY|O_CLOEXEC",
			},
			{
				ArgMeta: external.ArgMeta{
					Name: "mode",
					Type: "mode_t",
				},
				Value: 5038682,
			},
		},
	}
	triggerAntiDebuggingEvent = external.Event{
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
	triggerCodeInjectorEvent = external.Event{
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
)

func TestMain(m *testing.M) {
	flag.StringVar(&rulesDir, "enginerulesdir", "/Users/dpacak/dev/my_rulez/rego", "Path to Rego signatures directory")
	flag.StringVar(&helpersFilename, "enginehelpers", "/Users/dpacak/dev/my_rulez/helpers.rego", "Path to Rego helpers script (helpers.go)")

	flag.Parse()
	os.Exit(m.Run())
}

var (
	//go:embed testdata/helpers.rego
	helpersRego string
	//go:embed testdata/rego/anti_debugging_ptraceme.rego
	antiDebuggingRego string
	//go:embed testdata/rego/code_injection.rego
	codeInjectionRego string
)

func TestEngine(t *testing.T) {
	var err error
	var eng engine.Engine

	{
		modules := map[string]string{
			"anti_debugging_ptraceme.rego": antiDebuggingRego,
			"code_injection.rego":          codeInjectionRego,
			engine.ModuleNameHelpers:       helpersRego,
		}
		eng, err = engine.NewEngine(modules)
		require.NoError(t, err)
	}

	findings, err := eng.Eval(triggerAntiDebuggingEvent)
	require.NoError(t, err)
	assert.Equal(t, engine.Findings{
		{
			SigMetadata: types.SignatureMetadata{
				ID:          "TRC-2",
				Version:     "0.1.0",
				Name:        "Anti-Debugging",
				Description: "Process uses anti-debugging technique to block debugger",
				Tags:        []string{"linux", "container"},
				Properties: map[string]interface{}{
					"MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
					"Severity":     json.Number("3"),
				},
			},
			Context: triggerAntiDebuggingEvent,
			Data:    nil,
		},
	}, findings)

	findings, err = eng.Eval(triggerCodeInjectorEvent)
	require.NoError(t, err)
	assert.Equal(t, engine.Findings{
		{
			SigMetadata: types.SignatureMetadata{
				ID:          "TRC-3",
				Version:     "0.1.0",
				Name:        "Code injection",
				Description: "Possible code injection into another process",
				Tags:        []string{"linux", "container"},
				Properties: map[string]interface{}{
					"MITRE ATT&CK": "Defense Evasion: Process Injection",
					"Severity":     json.Number("3"),
				},
			},
			Context: triggerCodeInjectorEvent,
			Data: map[string]interface{}{
				"file flags": "o_rdwr",
				"file path":  "/proc/20/mem",
			},
		},
	}, findings)
}

func TestAIOEngine(t *testing.T) {
	var err error
	var eng engine.Engine

	{
		modules := map[string]string{
			"anti_debugging_ptraceme.rego": antiDebuggingRego,
			"code_injection.rego":          codeInjectionRego,
			"helpers.rego":                 helpersRego,
		}
		eng, err = engine.NewAIOEngine(modules)
		require.NoError(t, err)
	}

	findings, err := eng.Eval(triggerAntiDebuggingEvent)
	require.NoError(t, err)
	assert.Equal(t, engine.Findings{
		{
			SigMetadata: types.SignatureMetadata{
				ID:          "TRC-2",
				Version:     "0.1.0",
				Name:        "Anti-Debugging",
				Description: "Process uses anti-debugging technique to block debugger",
				Tags:        []string{"linux", "container"},
				Properties: map[string]interface{}{
					"MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
					"Severity":     json.Number("3"),
				},
			},
			Context: triggerAntiDebuggingEvent,
			Data:    nil,
		},
	}, findings)

	findings, err = eng.Eval(triggerCodeInjectorEvent)
	require.NoError(t, err)
	assert.Equal(t, engine.Findings{
		{
			SigMetadata: types.SignatureMetadata{
				ID:          "TRC-3",
				Version:     "0.1.0",
				Name:        "Code injection",
				Description: "Possible code injection into another process",
				Tags:        []string{"linux", "container"},
				Properties: map[string]interface{}{
					"MITRE ATT&CK": "Defense Evasion: Process Injection",
					"Severity":     json.Number("3"),
				},
			},
			Context: triggerCodeInjectorEvent,
			Data: map[string]interface{}{
				"file flags": "o_rdwr",
				"file path":  "/proc/20/mem",
			},
		},
	}, findings)
}

func TestGetPackageNameFromCode(t *testing.T) {
	pkgName, err := engine.GetPackageNameFromCode(`package tracee.TRC_2

tracee_match { 1 == 1 }
`)
	require.NoError(t, err)
	assert.Equal(t, "tracee.TRC_2", pkgName)
}
