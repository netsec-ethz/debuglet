// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"context"
	"errors"
	"mime"
	"net/http"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

type authoringCompiler interface {
	Build(context.Context, workflow.Workflow) (*Bundle, error)
	BuildExperiment(context.Context, workflow.Experiment) (*ExperimentBundle, error)
}

// authoringRoutes is shared by the loopback editor and the Unix-socket worker.
// The caller supplies the appropriate protection for mutation requests.
func authoringRoutes(mux *http.ServeMux, compiler authoringCompiler, prefix string, protect func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET "+prefix+"/catalog", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, workflow.Catalog())
	})
	mutation := func(experiment, build bool) http.HandlerFunc {
		return protect(func(w http.ResponseWriter, r *http.Request) {
			content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || content != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, errors.New("Content-Type must be application/json"))
				return
			}
			limit := int64(MaxWorkflowBytes)
			if experiment {
				limit = MaxExperimentBytes
			}
			if r.ContentLength > limit {
				writeError(w, http.StatusRequestEntityTooLarge, errors.New("authoring request exceeds its size limit"))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			var result any
			if experiment {
				var e workflow.Experiment
				e, err = DecodeExperiment(r.Body)
				if err == nil && !build {
					diagnostics := workflow.ValidateExperiment(e)
					if diagnostics == nil {
						diagnostics = []workflow.ExperimentDiagnostic{}
					}
					result = map[string]any{"diagnostics": diagnostics}
				} else if err == nil && compiler != nil {
					result, err = compiler.BuildExperiment(r.Context(), e)
					writeBuildResult(w, result, err)
					return
				}
			} else {
				var wf workflow.Workflow
				wf, err = DecodeWorkflow(r.Body)
				if err == nil && !build {
					diagnostics := workflow.Validate(wf)
					if diagnostics == nil {
						diagnostics = []workflow.Diagnostic{}
					}
					result = map[string]any{"diagnostics": diagnostics}
				} else if err == nil && compiler != nil {
					result, err = compiler.Build(r.Context(), wf)
					writeBuildResult(w, result, err)
					return
				}
			}
			if err != nil {
				status := http.StatusBadRequest
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				writeError(w, status, err)
				return
			}
			if build && compiler == nil {
				writeError(w, http.StatusServiceUnavailable, errors.New("compiler is unavailable; configure the matching Debuglet SDK"))
				return
			}
			writeJSON(w, http.StatusOK, result)
		})
	}
	mux.HandleFunc("POST "+prefix+"/validate", mutation(false, false))
	mux.HandleFunc("POST "+prefix+"/build", mutation(false, true))
	mux.HandleFunc("POST "+prefix+"/experiments/validate", mutation(true, false))
	mux.HandleFunc("POST "+prefix+"/experiments/build", mutation(true, true))
}

func writeBuildResult(w http.ResponseWriter, result any, err error) {
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
