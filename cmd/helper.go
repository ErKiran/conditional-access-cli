package cmd

import (
	"ca-cli/graph"
	"sync"
)

var (
	once           sync.Once
	sharedGraph    *graph.GraphHelper
	sharedGraphErr error
)

func getGraphHelper() (*graph.GraphHelper, error) {
	once.Do(func() {
		sharedGraph = graph.NewGraphHelper()
		sharedGraphErr = sharedGraph.InitializeGraphForAppAuth()
	})
	return sharedGraph, sharedGraphErr
}
