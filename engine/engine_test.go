package engine_test

import (
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

func TestEngine(t *testing.T) {
	var err error
	var eng engine.Engine

	{
		helpers, err := engine.GetFileContentAsString(helpersFilename)
		require.NoError(t, err)
		modules, err := engine.GetModulesFromDir(rulesDir)
		require.NoError(t, err)

		eng, err = engine.NewEngine(modules, helpers)
		require.NoError(t, err)
	}

	findings, err := eng.Eval(triggerAntiDebuggingEvent)
	require.NoError(t, err)
	assert.Equal(t, engine.Findings{
		{
			SigMetadata: types.SignatureMetadata{
				ID:          "TRC-2",
				Version:     "0.1.0",
				Name:        "Anti-Debugging Detected",
				Description: "A Process used anti-debugging technique to block a debugger. Malwares use anti-debugging to stay invisible and prevent their behavior being analyzed.",
				Tags:        []string{"linux", "container"},
				Properties: map[string]interface{}{
					"Category":             "defense-evasion",
					"Kubernetes_Technique": "",
					"Severity":             json.Number("3"),
					"Technique":            "Execution Guardrails",
					"external_id":          "T1480",
					"id":                   "attack-pattern--853c4192-4311-43e1-bfbb-b11b14911852",
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
				Name:        "Code Injection Detected",
				Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malwares.",
				Tags:        []string{"linux", "container"},
				Properties: map[string]interface{}{
					"Category":             "defense-evasion",
					"Kubernetes_Technique": "",
					"Severity":             json.Number("3"),
					"Technique":            "Process Injection",
					"external_id":          "T1055",
					"id":                   "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d"},
			},
			Context: triggerCodeInjectorEvent,
			Data: map[string]interface{}{
				"File Flags": "o_rdwr",
				"File Path":  "/proc/20/mem",
			},
		},
	}, findings)
}

func TestAIOEngine(t *testing.T) {
	var err error
	var eng engine.Engine

	{
		helpers, err := engine.GetFileContentAsString(helpersFilename)
		require.NoError(t, err)
		modules, err := engine.GetModulesFromDir(rulesDir)
		require.NoError(t, err)
		modules["helpers.rego"] = helpers

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
				Name:        "Anti-Debugging Detected",
				Description: "A Process used anti-debugging technique to block a debugger. Malwares use anti-debugging to stay invisible and prevent their behavior being analyzed.",
				Tags:        []string{"linux", "container"},
				Properties: map[string]interface{}{
					"Category":             "defense-evasion",
					"Kubernetes_Technique": "",
					"Severity":             json.Number("3"),
					"Technique":            "Execution Guardrails",
					"external_id":          "T1480",
					"id":                   "attack-pattern--853c4192-4311-43e1-bfbb-b11b14911852",
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
				Name:        "Code Injection Detected",
				Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malwares.",
				Tags:        []string{"linux", "container"},
				Properties: map[string]interface{}{
					"Category":             "defense-evasion",
					"Kubernetes_Technique": "",
					"Severity":             json.Number("3"),
					"Technique":            "Process Injection",
					"external_id":          "T1055",
					"id":                   "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d"},
			},
			Context: triggerCodeInjectorEvent,
			Data: map[string]interface{}{
				"File Flags": "o_rdwr",
				"File Path":  "/proc/20/mem",
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
