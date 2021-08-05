package engine_test

import (
	"testing"

	"github.com/danielpacak/opa-herculean/engine"
	"github.com/stretchr/testify/require"
)

func BenchmarkEngine(b *testing.B) {
	var err error
	var eng engine.Engine

	{
		helpers, err := engine.GetFileContentAsString(helpersFilename)
		require.NoError(b, err)
		modules, err := engine.GetModulesFromDir(rulesDir)
		require.NoError(b, err)

		eng, err = engine.NewEngine(modules, helpers)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = eng.Eval(triggerAntiDebuggingEvent)
		require.NoError(b, err)
		_, err = eng.Eval(triggerCodeInjectorEvent)
		require.NoError(b, err)
	}
}

func BenchmarkAIOEngine(b *testing.B) {
	var err error
	var eng engine.Engine

	{
		helpers, err := engine.GetFileContentAsString(helpersFilename)
		require.NoError(b, err)
		modules, err := engine.GetModulesFromDir(rulesDir)
		require.NoError(b, err)
		modules["helpers.rego"] = helpers

		eng, err = engine.NewAIOEngine(modules)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = eng.Eval(triggerAntiDebuggingEvent)
		require.NoError(b, err)
		_, err = eng.Eval(triggerCodeInjectorEvent)
		require.NoError(b, err)
	}
}
