// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func (h *Handler) registerMeasurementRoutes(e *echo.Echo) {
	e.GET("/measurements", h.ListMeasurements)
	e.GET("/measurements/:id", h.GetMeasurement)
	e.GET("/debuglet/:id/detail", h.GetRunDetail)
	e.GET("/measurement-templates", h.GetMeasurementTemplates)
	e.GET("/measurement-profiles", h.ListMeasurementProfiles)
	e.POST("/measurement-profiles", h.CreateMeasurementProfile)
	e.GET("/measurement-profiles/:id", h.GetMeasurementProfile)
	e.PUT("/measurement-profiles/:id", h.UpdateMeasurementProfile)
	e.DELETE("/measurement-profiles/:id", h.DeleteMeasurementProfile)
}

// GetMeasurementTemplates publishes immutable versioned starter definitions.
// The program is shipped by the pinned companion dashboard, not fetched from
// an arbitrary URL. Its digest is checked again on profile creation.
func (h *Handler) GetMeasurementTemplates(c echo.Context) error {
	if _, err := requireCaller(c); err != nil {
		return err
	}
	items := make([]wire.MeasurementTemplate, 0, 3)
	for _, item := range []struct{ id, name, description, target string }{
		{"http", "HTTP timing & status", "Make one HTTP request and check its response status and time.", "HTTP or HTTPS URL"},
		{"tcp", "TCP connection", "Check whether one service accepts a TCP connection.", "host:port"},
		{"service", "Service readiness", "Check two HTTP endpoints and optional response text.", "HTTP or HTTPS URL"},
	} {
		properties := map[string]wire.TemplateArgument{
			"target": {Type: "string", Description: item.target},
			"max_ms": {Type: "string", Description: "Optional positive duration threshold in milliseconds"},
		}
		required := []string{"target"}
		if item.id == "service" {
			properties["check"] = wire.TemplateArgument{Type: "string", Description: "Second HTTP or HTTPS URL"}
			properties["contains"] = wire.TemplateArgument{Type: "string", Description: "Optional text required in the second response"}
			required = append(required, "check")
		}
		items = append(items, wire.MeasurementTemplate{
			ID: item.id, Version: 1, Name: item.name, Description: item.description,
			ProgramSHA256: wire.ProbeSHA256, ProgramAsset: "templates/probe.wasm",
			Arguments:          wire.TemplateArguments{Type: "object", Properties: properties, Required: required},
			RequiredTransports: []string{"tcp"},
			DefaultPolicy:      wire.Policy{FloorBW: 100000, CeilBW: 100000, TimeoutMS: 30000, Addresses: []string{}},
		})
	}
	return c.JSON(http.StatusOK, items)
}

func profileNotFound() error { return apiError(http.StatusNotFound, CodeNotFound, "profile not found") }
func profileFailure(err error) error {
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "profile storage failed", err)
}

func decodeProfile(c echo.Context) (wire.ProfileConfig, string, error) {
	var config wire.ProfileConfig
	body := http.MaxBytesReader(c.Response(), c.Request().Body, wire.MaxProfileBytes)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, "", profileDecodeError(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err != nil {
			return config, "", profileDecodeError(err)
		}
		return config, "", apiError(http.StatusBadRequest, CodeInvalidRequest, "expected one profile document")
	}
	invalid := func(message string) (wire.ProfileConfig, string, error) {
		return config, "", apiError(http.StatusBadRequest, CodeInvalidRequest, message)
	}
	if config.Version != wire.ProfileVersion {
		return invalid("unsupported profile version; expected version 1")
	}
	if strings.TrimSpace(config.Name) == "" || len(config.Name) > 120 {
		return invalid("profile name must contain 1 to 120 bytes")
	}
	if strings.TrimSpace(config.ExecutorID) == "" || len(config.ExecutorID) > 256 {
		return invalid("profile requires an executor ID of at most 256 bytes")
	}
	if len(config.Args) > 256 || len(config.Policy.Addresses) > 256 {
		return invalid("profile arguments and destinations are limited to 256 entries each")
	}
	argumentBytes := 0
	for _, arg := range config.Args {
		argumentBytes += len(arg)
		if strings.ContainsRune(arg, 0) {
			return invalid("profile arguments cannot contain NUL")
		}
	}
	for _, address := range config.Policy.Addresses {
		argumentBytes += len(address)
	}
	if argumentBytes > 128<<10 {
		return invalid("profile arguments and destinations exceed 128 KiB")
	}
	if err := validatePolicy(0, config.Policy); err != nil {
		return config, "", err
	}
	if !bytes.HasPrefix(config.Program.Wasm, []byte{0, 97, 115, 109, 1, 0, 0, 0}) {
		return invalid("profile program must be a WebAssembly version 1 module")
	}
	digest := sha256.Sum256(config.Program.Wasm)
	if config.Program.SHA256 != hex.EncodeToString(digest[:]) {
		return invalid("profile program digest does not match its bytes")
	}
	if ref := config.Template; ref != nil {
		if ref.Version != 1 || (ref.ID != "http" && ref.ID != "tcp" && ref.ID != "service") || config.Program.SHA256 != wire.ProbeSHA256 {
			return invalid("template version or program digest does not match the catalogue")
		}
	}
	if config.Args == nil {
		config.Args = []string{}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return config, "", profileFailure(err)
	}
	if len(encoded) > wire.MaxProfileBytes {
		return config, "", apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "profile exceeds 8 MiB")
	}
	return config, string(encoded), nil
}

func profileDecodeError(err error) error {
	var exceeded *http.MaxBytesError
	if errors.As(err, &exceeded) {
		return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "profile exceeds 8 MiB")
	}
	return bindError(err)
}

func (h *Handler) CreateMeasurementProfile(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	config, encoded, err := decodeProfile(c)
	if err != nil {
		return err
	}
	id := uuid.NewString()
	n, err := database.New(h.db).CreateMeasurementProfile(c.Request().Context(), database.CreateMeasurementProfileParams{ID: id, Document: encoded, Uuid: caller.UserUUID})
	if err != nil {
		return profileFailure(err)
	}
	if n != 1 {
		return apiError(http.StatusConflict, CodeInvalidRequest, "profile limit reached; delete an unused profile before saving another")
	}
	return c.JSON(http.StatusCreated, wire.Profile{ID: id, Config: config})
}

func (h *Handler) GetMeasurementProfile(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	document, err := database.New(h.db).GetMeasurementProfile(c.Request().Context(), database.GetMeasurementProfileParams{ID: c.Param("id"), Uuid: caller.UserUUID})
	if errors.Is(err, sql.ErrNoRows) {
		return profileNotFound()
	}
	if err != nil {
		return profileFailure(err)
	}
	var config wire.ProfileConfig
	if err := json.Unmarshal([]byte(document), &config); err != nil {
		return profileFailure(err)
	}
	return c.JSON(http.StatusOK, wire.Profile{ID: c.Param("id"), Config: config})
}

func (h *Handler) ListMeasurementProfiles(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	rows, err := database.New(h.db).ListMeasurementProfiles(c.Request().Context(), caller.UserUUID)
	if err != nil {
		return profileFailure(err)
	}
	items := make([]wire.ProfileSummary, 0, len(rows))
	for _, row := range rows {
		items = append(items, wire.ProfileSummary{ID: row.ID, Name: row.Name, ProgramSHA256: row.ProgramSha256})
	}
	return c.JSON(http.StatusOK, items)
}

func (h *Handler) UpdateMeasurementProfile(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	config, encoded, err := decodeProfile(c)
	if err != nil {
		return err
	}
	n, err := database.New(h.db).UpdateMeasurementProfile(c.Request().Context(), database.UpdateMeasurementProfileParams{ID: c.Param("id"), Document: encoded, Uuid: caller.UserUUID})
	if err != nil {
		return profileFailure(err)
	}
	if n != 1 {
		return profileNotFound()
	}
	return c.JSON(http.StatusOK, wire.Profile{ID: c.Param("id"), Config: config})
}

func (h *Handler) DeleteMeasurementProfile(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	n, err := database.New(h.db).DeleteMeasurementProfile(c.Request().Context(), database.DeleteMeasurementProfileParams{ID: c.Param("id"), Uuid: caller.UserUUID})
	if err != nil {
		return profileFailure(err)
	}
	if n != 1 {
		return profileNotFound()
	}
	return c.NoContent(http.StatusNoContent)
}
