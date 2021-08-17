package engine_test

import (
	"flag"
	"os"
	"testing"

	"github.com/danielpacak/opa-herculean/engine"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	flag.StringVar(&rulesDir, "enginerulesdir", "/Users/dpacak/dev/my_rulez/rego", "Path to Rego signatures directory")
	flag.StringVar(&helpersFilename, "enginehelpers", "/Users/dpacak/dev/my_rulez/helpers.rego", "Path to Rego helpers script (helpers.go)")

	flag.Parse()
	os.Exit(m.Run())
}

func BenchmarkEngineWithRawInput(b *testing.B) {
	var err error
	var eng engine.Engine

	{
		helpers, err := engine.GetFileContentAsString(helpersFilename)
		require.NoError(b, err)
		modules, err := engine.GetModulesFromDir(rulesDir)
		require.NoError(b, err)
		modules[engine.ModuleNameHelpers] = helpers

		eng, err = engine.NewEngine(modules)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = eng.Eval(triggerAntiDebuggingEvent)
		require.NoError(b, err)
		_, err = eng.Eval(triggerCodeInjectionEvent)
		require.NoError(b, err)
	}
}

func BenchmarkEngineWithParsedInput(b *testing.B) {
	var err error
	var eng engine.Engine

	{
		helpers, err := engine.GetFileContentAsString(helpersFilename)
		require.NoError(b, err)
		modules, err := engine.GetModulesFromDir(rulesDir)
		require.NoError(b, err)
		modules[engine.ModuleNameHelpers] = helpers

		eng, err = engine.NewEngine(modules)
		require.NoError(b, err)
	}

	var parsedAntiDebuggingEvent engine.ParsedEvent
	var parsedCodeInjectionEvent engine.ParsedEvent

	{
		parsedAntiDebuggingEvent, err = engine.ToParsedEvent(triggerAntiDebuggingEvent)
		require.NoError(b, err)
		parsedCodeInjectionEvent, err = engine.ToParsedEvent(triggerCodeInjectionEvent)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = eng.Eval(parsedAntiDebuggingEvent)
		require.NoError(b, err)
		_, err = eng.Eval(parsedCodeInjectionEvent)
		require.NoError(b, err)
	}
}

func BenchmarkAIOEngineWithRawInput(b *testing.B) {
	var err error
	var eng engine.Engine

	{
		helpers, err := engine.GetFileContentAsString(helpersFilename)
		require.NoError(b, err)
		modules, err := engine.GetModulesFromDir(rulesDir)
		require.NoError(b, err)
		modules[engine.ModuleNameHelpers] = helpers

		eng, err = engine.NewAIOEngine(modules)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = eng.Eval(triggerAntiDebuggingEvent)
		require.NoError(b, err)
		_, err = eng.Eval(triggerCodeInjectionEvent)
		require.NoError(b, err)
	}
}
