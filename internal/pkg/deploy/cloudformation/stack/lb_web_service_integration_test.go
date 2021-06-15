// +build integration localintegration

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package stack_test

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/aws/copilot-cli/internal/pkg/deploy/cloudformation/stack"
	"github.com/aws/copilot-cli/internal/pkg/template"

	"github.com/aws/copilot-cli/internal/pkg/manifest"

	"github.com/stretchr/testify/require"
)

const (
	svcManifestPath = "svc-manifest.yml"
	svcStackPath    = "svc-test.stack.yml"
	svcParamsPath   = "svc-test.params.json"
)

func TestLoadBalancedWebService_Template(t *testing.T) {
	path := filepath.Join("testdata", "workloads", svcManifestPath)
	manifestBytes, err := ioutil.ReadFile(path)
	require.NoError(t, err)
	mft, err := manifest.UnmarshalWorkload(manifestBytes)
	require.NoError(t, err)
	envMft, err := mft.ApplyEnv(envName)
	require.NoError(t, err)
	v, ok := envMft.(*manifest.LoadBalancedWebService)
	require.True(t, ok)

	serializer, err := stack.NewHTTPSLoadBalancedWebService(v, envName, appName, stack.RuntimeConfig{
		Partition: "aws",
	})

	tpl, err := serializer.Template()
	require.NoError(t, err, "template should render")
	regExpGUID := regexp.MustCompile(`([a-f\d]{8}-)([a-f\d]{4}-){3}([a-f\d]{12})`) // Matches random guids
	testName := fmt.Sprintf("CF Template should be equal")
	parser := template.New()
	envController, err := parser.Read(envControllerPath)
	require.NoError(t, err)
	zipFile := envController.String()
	t.Run(testName, func(t *testing.T) {
		actualBytes := []byte(tpl)
		// Cut random GUID from template.
		actualBytes = regExpGUID.ReplaceAll(actualBytes, []byte("RandomGUID"))
		actualString := string(actualBytes)
		// Cut out zip file from EnvControllerAction for more readable output
		actualString = strings.ReplaceAll(actualString, zipFile, "Abracadabra")
		actualBytes = []byte(actualString)
		mActual := make(map[interface{}]interface{})
		require.NoError(t, yaml.Unmarshal(actualBytes, mActual))

		expected, err := ioutil.ReadFile(filepath.Join("testdata", "workloads", svcStackPath))
		require.NoError(t, err, "should be able to read expected bytes")
		expectedBytes := []byte(expected)
		mExpected := make(map[interface{}]interface{})
		require.NoError(t, yaml.Unmarshal(expectedBytes, mExpected))
		require.Equal(t, mExpected, mActual)
	})

	testName = fmt.Sprintf("Parameter values should render properly")
	t.Run(testName, func(t *testing.T) {
		actualParams, err := serializer.SerializedParameters()
		require.NoError(t, err)

		path := filepath.Join("testdata", "workloads", svcParamsPath)
		wantedCFNParamsBytes, err := ioutil.ReadFile(path)
		require.NoError(t, err)

		require.Equal(t, string(wantedCFNParamsBytes), actualParams)
	})
}
