// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func (h *Handler) registerCommunityRoutes(e *echo.Echo) {
	e.GET("/communities", h.ListCommunities)
	e.POST("/communities", h.CreateCommunity)
	e.GET("/communities/:id", h.GetCommunity)
	e.PATCH("/communities/:id", h.UpdateCommunity)
	e.GET("/communities/:id/members", h.ListCommunityMembers)
	e.POST("/communities/:id/invitations", h.CreateCommunityInvitation)
	e.POST("/community-invitations/accept", h.AcceptCommunityInvitation)
	e.DELETE("/communities/:id/members/:user_id", h.RemoveCommunityMember)
	e.GET("/communities/:id/projects", h.ListCommunityProjects)
	e.POST("/communities/:id/projects", h.CreateCommunityProject)
	e.GET("/community-projects/:id", h.GetCommunityProject)
	e.PATCH("/community-projects/:id", h.UpdateCommunityProject)
	e.GET("/community-projects/:id/experiments", h.ListCommunityExperiments)
	e.POST("/community-projects/:id/experiments", h.CreateCommunityExperiment)
	e.GET("/community-experiments/:id", h.GetCommunityExperiment)
	e.PUT("/community-experiments/:id", h.UpdateCommunityExperiment)
	e.DELETE("/community-experiments/:id", h.DeleteCommunityExperiment)
	e.GET("/community-projects/:id/measurements", h.ListCommunityMeasurements)
	e.POST("/community-projects/:id/measurements", h.ShareCommunityMeasurement)
	e.DELETE("/community-projects/:id/measurements/:measurement_id", h.UnshareCommunityMeasurement)
}

func communityNotFound() error {
	return apiError(http.StatusNotFound, CodeNotFound, "community resource not found")
}
func communityFailure(err error) error {
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "community storage failed", err)
}
func communityConflict(message string) error {
	return apiError(http.StatusConflict, CodeInvalidRequest, message)
}

func (h *Handler) requireCommunity(c echo.Context, id string, ownerOnly bool) (database.GetCommunityRow, error) {
	account, err := requireAccount(c)
	if err != nil {
		return database.GetCommunityRow{}, err
	}
	row, err := database.New(h.db).GetCommunity(c.Request().Context(), database.GetCommunityParams{ID: id, UserUuid: account.UserUUID})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && ownerOnly && row.Role != "owner") {
		return row, communityNotFound()
	}
	if err != nil {
		return row, communityFailure(err)
	}
	return row, nil
}

func (h *Handler) requireCommunityProject(c echo.Context, id string) (database.GetCommunityProjectRow, error) {
	account, err := requireAccount(c)
	if err != nil {
		return database.GetCommunityProjectRow{}, err
	}
	row, err := database.New(h.db).GetCommunityProject(c.Request().Context(), database.GetCommunityProjectParams{ID: id, UserUuid: account.UserUUID})
	if errors.Is(err, sql.ErrNoRows) {
		return row, communityNotFound()
	}
	if err != nil {
		return row, communityFailure(err)
	}
	return row, nil
}

func communityView(row database.GetCommunityRow) wire.Community {
	return wire.Community{
		ID: row.ID, Name: row.Name, Description: row.Description, Role: row.Role,
		CreatedBy: row.CreatorUuid.String(), CreatedAt: time.Unix(row.CreatedAt, 0).UTC(),
	}
}
func projectView(row database.GetCommunityProjectRow) wire.CommunityProject {
	return wire.CommunityProject{
		ID: row.ID, CommunityID: row.CommunityID, Name: row.Name, Description: row.Description,
		CreatedBy: row.CreatorUuid.String(), CreatedAt: time.Unix(row.CreatedAt, 0).UTC(),
	}
}
func experimentView(row database.GetCommunityExperimentRow) wire.CommunityExperiment {
	return wire.CommunityExperiment{
		ID: row.ID, ProjectID: row.ProjectID, Name: row.Name, Description: row.Description,
		Collection: row.Collection, Kind: row.Kind, Revision: row.Revision,
		CreatedBy: row.CreatorUuid.String(), UpdatedAt: time.Unix(row.UpdatedAt, 0).UTC(),
		Document: json.RawMessage(row.Document), Bundle: json.RawMessage(row.Bundle.String),
	}
}
func sharedMeasurementView(row database.GetCommunityMeasurementRow) wire.CommunityMeasurement {
	item := wire.CommunityMeasurement{ProjectID: row.ProjectID, MeasurementID: row.MeasurementID, SharedBy: row.SharerUuid.String(), SharedAt: time.Unix(row.SharedAt, 0).UTC(), ExperimentID: row.ExperimentID.String}
	if row.ExperimentRevision.Valid {
		revision := row.ExperimentRevision.Int64
		item.ExperimentRevision = &revision
	}
	return item
}

type communityNameRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func readCommunityName(c echo.Context) (communityNameRequest, error) {
	var input communityNameRequest
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 8<<10)
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return input, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 120 || len(input.Description) > 2000 {
		return input, apiError(http.StatusBadRequest, CodeInvalidRequest, "name must contain 1 to 120 bytes and description at most 2000 bytes")
	}
	return input, nil
}

func (h *Handler) ListCommunities(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	rows, err := database.New(h.db).ListCommunities(c.Request().Context(), account.UserUUID)
	if err != nil {
		return communityFailure(err)
	}
	items := make([]wire.Community, 0, len(rows))
	for _, row := range rows {
		items = append(items, communityView(database.GetCommunityRow(row)))
	}
	return c.JSON(http.StatusOK, items)
}
func (h *Handler) GetCommunity(c echo.Context) error {
	row, err := h.requireCommunity(c, c.Param("id"), false)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, communityView(row))
}
func (h *Handler) CreateCommunity(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	input, err := readCommunityName(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return communityFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	id := uuid.NewString()
	n, err := q.CreateCommunity(ctx, database.CreateCommunityParams{ID: id, Name: input.Name, Description: input.Description, CreatedAt: time.Now().Unix(), UserUuid: account.UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityConflict("an account may create at most 16 communities")
	}
	if err = q.AddCommunityCreator(ctx, id); err != nil {
		return communityFailure(err)
	}
	if err = tx.Commit(); err != nil {
		return communityFailure(err)
	}
	row, err := h.requireCommunity(c, id, false)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, communityView(row))
}
func (h *Handler) UpdateCommunity(c echo.Context) error {
	if _, err := h.requireCommunity(c, c.Param("id"), true); err != nil {
		return err
	}
	input, err := readCommunityName(c)
	if err != nil {
		return err
	}
	n, err := database.New(h.db).UpdateCommunity(c.Request().Context(), database.UpdateCommunityParams{ID: c.Param("id"), Name: input.Name, Description: input.Description, UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityNotFound()
	}
	return h.GetCommunity(c)
}
func (h *Handler) ListCommunityMembers(c echo.Context) error {
	if _, err := h.requireCommunity(c, c.Param("id"), false); err != nil {
		return err
	}
	rows, err := database.New(h.db).ListCommunityMembers(c.Request().Context(), database.ListCommunityMembersParams{ID: c.Param("id"), UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	items := make([]wire.CommunityMember, 0, len(rows))
	for _, row := range rows {
		items = append(items, wire.CommunityMember{UserID: row.UserUuid.String(), Name: row.Name, Role: row.Role, JoinedAt: time.Unix(row.JoinedAt, 0).UTC()})
	}
	return c.JSON(http.StatusOK, items)
}
func (h *Handler) RemoveCommunityMember(c echo.Context) error {
	community, err := h.requireCommunity(c, c.Param("id"), true)
	if err != nil {
		return err
	}
	member, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return communityNotFound()
	}
	if member == community.CreatorUuid {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "the community owner cannot be removed")
	}
	n, err := database.New(h.db).RemoveCommunityMember(c.Request().Context(), database.RemoveCommunityMemberParams{ID: community.ID, MemberUuid: member, UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityNotFound()
	}
	return c.NoContent(http.StatusNoContent)
}
func (h *Handler) CreateCommunityInvitation(c echo.Context) error {
	community, err := h.requireCommunity(c, c.Param("id"), true)
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return communityFailure(err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	expires := now.Add(7 * 24 * time.Hour)
	q := database.New(h.db)
	ctx := c.Request().Context()
	if err = q.PruneCommunityInvitations(ctx, database.PruneCommunityInvitationsParams{CommunityID: community.ID, ExpiresAt: now.Unix()}); err != nil {
		return communityFailure(err)
	}
	n, err := q.CreateCommunityInvitation(ctx, database.CreateCommunityInvitationParams{TokenHash: hash[:], ID: community.ID, ExpiresAt: expires.Unix(), Now: now.Unix(), UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityConflict("a community may have at most 8 active invitations")
	}
	return c.JSON(http.StatusCreated, struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}{token, expires})
}
func (h *Handler) AcceptCommunityInvitation(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	var input struct {
		Token string `json:"token"`
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 1024)
	if err = decodeMeasurementRequest(c, &input); err != nil {
		return err
	}
	if len(input.Token) != 43 {
		return communityNotFound()
	}
	hash := sha256.Sum256([]byte(input.Token))
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return communityFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	id, err := q.ConsumeCommunityInvitation(ctx, database.ConsumeCommunityInvitationParams{TokenHash: hash[:], Now: time.Now().Unix(), UserUuid: account.UserUUID})
	if errors.Is(err, sql.ErrNoRows) {
		return communityNotFound()
	}
	if err != nil {
		return communityFailure(err)
	}
	if err = q.JoinCommunity(ctx, database.JoinCommunityParams{ID: id, JoinedAt: time.Now().Unix(), UserUuid: account.UserUUID}); err != nil {
		return communityFailure(err)
	}
	if err = tx.Commit(); err != nil {
		return communityFailure(err)
	}
	row, err := h.requireCommunity(c, id, false)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, communityView(row))
}

func (h *Handler) ListCommunityProjects(c echo.Context) error {
	if _, err := h.requireCommunity(c, c.Param("id"), false); err != nil {
		return err
	}
	rows, err := database.New(h.db).ListCommunityProjects(c.Request().Context(), database.ListCommunityProjectsParams{CommunityID: c.Param("id"), UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	items := make([]wire.CommunityProject, 0, len(rows))
	for _, row := range rows {
		items = append(items, wire.CommunityProject{ID: row.ID, CommunityID: row.CommunityID, Name: row.Name, Description: row.Description, CreatedBy: row.CreatorUuid.String(), CreatedAt: time.Unix(row.CreatedAt, 0).UTC()})
	}
	return c.JSON(http.StatusOK, items)
}
func (h *Handler) GetCommunityProject(c echo.Context) error {
	row, err := h.requireCommunityProject(c, c.Param("id"))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, projectView(row))
}
func (h *Handler) CreateCommunityProject(c echo.Context) error {
	if _, err := h.requireCommunity(c, c.Param("id"), false); err != nil {
		return err
	}
	input, err := readCommunityName(c)
	if err != nil {
		return err
	}
	id := uuid.NewString()
	n, err := database.New(h.db).CreateCommunityProject(c.Request().Context(), database.CreateCommunityProjectParams{ID: id, CommunityID: c.Param("id"), Name: input.Name, Description: input.Description, CreatedAt: time.Now().Unix(), UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityConflict("a community may have at most 64 projects")
	}
	row, err := h.requireCommunityProject(c, id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, projectView(row))
}
func (h *Handler) UpdateCommunityProject(c echo.Context) error {
	if _, err := h.requireCommunityProject(c, c.Param("id")); err != nil {
		return err
	}
	input, err := readCommunityName(c)
	if err != nil {
		return err
	}
	n, err := database.New(h.db).UpdateCommunityProject(c.Request().Context(), database.UpdateCommunityProjectParams{ID: c.Param("id"), Name: input.Name, Description: input.Description, UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityNotFound()
	}
	return h.GetCommunityProject(c)
}

type communityExperimentRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Collection  string          `json:"collection,omitempty"`
	Kind        string          `json:"kind"`
	Document    json.RawMessage `json:"document"`
	Bundle      json.RawMessage `json:"bundle,omitempty"`
	Revision    int64           `json:"revision,omitempty"`
}

func readCommunityExperiment(c echo.Context) (communityExperimentRequest, error) {
	var input communityExperimentRequest
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, wire.MaxCommunityExperimentBytes)
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return input, err
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Collection = strings.TrimSpace(input.Collection)
	if input.Name == "" || len(input.Name) > 120 || len(input.Description) > 4000 || len(input.Collection) > 120 {
		return input, apiError(http.StatusBadRequest, CodeInvalidRequest, "experiment name and collection are limited to 120 bytes and description to 4000 bytes")
	}
	var err error
	input.Document, input.Bundle, err = validateCommunityDocument(input.Kind, input.Document, input.Bundle)
	if err != nil {
		return input, err
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return input, communityFailure(err)
	}
	if len(encoded) > wire.MaxCommunityExperimentBytes {
		return input, apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "saved experiment exceeds 24 MiB")
	}
	return input, nil
}
func (h *Handler) ListCommunityExperiments(c echo.Context) error {
	if _, err := h.requireCommunityProject(c, c.Param("id")); err != nil {
		return err
	}
	rows, err := database.New(h.db).ListCommunityExperiments(c.Request().Context(), database.ListCommunityExperimentsParams{ProjectID: c.Param("id"), UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	items := make([]wire.CommunityExperiment, 0, len(rows))
	for _, row := range rows {
		items = append(items, wire.CommunityExperiment{ID: row.ID, ProjectID: row.ProjectID, Name: row.Name, Description: row.Description, Collection: row.Collection, Kind: row.Kind, Revision: row.Revision, CreatedBy: row.CreatorUuid.String(), UpdatedAt: time.Unix(row.UpdatedAt, 0).UTC()})
	}
	return c.JSON(http.StatusOK, items)
}
func (h *Handler) GetCommunityExperiment(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	revision := int64(0)
	if value := c.QueryParam("revision"); value != "" {
		revision, err = strconv.ParseInt(value, 10, 64)
		if err != nil || revision < 1 {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "revision must be a positive integer")
		}
	}
	row, err := database.New(h.db).GetCommunityExperiment(c.Request().Context(), database.GetCommunityExperimentParams{ID: c.Param("id"), Revision: revision, UserUuid: account.UserUUID})
	if errors.Is(err, sql.ErrNoRows) {
		return communityNotFound()
	}
	if err != nil {
		return communityFailure(err)
	}
	return c.JSON(http.StatusOK, experimentView(row))
}
func (h *Handler) CreateCommunityExperiment(c echo.Context) error {
	if _, err := h.requireCommunityProject(c, c.Param("id")); err != nil {
		return err
	}
	input, err := readCommunityExperiment(c)
	if err != nil {
		return err
	}
	if input.Revision != 0 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "new experiments do not specify a revision")
	}
	return h.saveCommunityExperiment(c, input, uuid.NewString(), true)
}
func (h *Handler) UpdateCommunityExperiment(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	_, err = database.New(h.db).GetCommunityExperiment(c.Request().Context(), database.GetCommunityExperimentParams{ID: c.Param("id"), Revision: 0, UserUuid: account.UserUUID})
	if errors.Is(err, sql.ErrNoRows) {
		return communityNotFound()
	}
	if err != nil {
		return communityFailure(err)
	}
	input, err := readCommunityExperiment(c)
	if err != nil {
		return err
	}
	if input.Revision < 1 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "updating an experiment requires its current revision")
	}
	return h.saveCommunityExperiment(c, input, c.Param("id"), false)
}
func (h *Handler) DeleteCommunityExperiment(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	q := database.New(h.db)
	experiment, err := q.GetCommunityExperiment(ctx, database.GetCommunityExperimentParams{ID: c.Param("id"), UserUuid: account.UserUUID})
	if errors.Is(err, sql.ErrNoRows) {
		return communityNotFound()
	}
	if err != nil {
		return communityFailure(err)
	}
	if experiment.CreatorUuid != account.UserUUID {
		project, err := h.requireCommunityProject(c, experiment.ProjectID)
		if err != nil {
			return err
		}
		if _, err := h.requireCommunity(c, project.CommunityID, true); err != nil {
			return err
		}
	}
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return communityFailure(err)
	}
	defer tx.Rollback()
	if err := pruneUnadmittedCommunityShares(ctx, tx, experiment.ProjectID); err != nil {
		return communityFailure(err)
	}
	deleted, err := database.New(tx).DeleteCommunityExperiment(ctx, database.DeleteCommunityExperimentParams{ID: experiment.ID, UserUuid: account.UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if deleted != 1 {
		return communityConflict("experiment is referenced by shared measurements or pending runs; remove those references before deleting it")
	}
	if err := tx.Commit(); err != nil {
		return communityFailure(err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) saveCommunityExperiment(c echo.Context, input communityExperimentRequest, id string, create bool) error {
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return communityFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	account := requestCaller(c)
	revision := input.Revision + 1
	var n int64
	if create {
		n, err = q.CreateCommunityExperiment(ctx, database.CreateCommunityExperimentParams{ID: id, ProjectID: c.Param("id"), UserUuid: account.UserUUID})
	} else {
		n, err = q.AdvanceCommunityExperiment(ctx, database.AdvanceCommunityExperimentParams{ID: id, Revision: input.Revision, UserUuid: account.UserUUID})
	}
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityConflict("experiment changed or its limit was reached; reload before editing, or save a new experiment")
	}
	n, err = q.InsertCommunityExperimentRevision(ctx, database.InsertCommunityExperimentRevisionParams{ExperimentID: id, Revision: revision, Name: input.Name, Description: input.Description, Collection: input.Collection, Kind: input.Kind, Document: string(input.Document), Bundle: sql.NullString{String: string(input.Bundle), Valid: len(input.Bundle) > 0}, UpdatedAt: time.Now().Unix()})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityConflict("community saved experiments exceed 256 MiB; delete unused saved experiments before saving another")
	}
	row, err := q.GetCommunityExperiment(ctx, database.GetCommunityExperimentParams{ID: id, Revision: revision, UserUuid: account.UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if err = tx.Commit(); err != nil {
		return communityFailure(err)
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	return c.JSON(status, experimentView(row))
}
func (h *Handler) ListCommunityMeasurements(c echo.Context) error {
	if _, err := h.requireCommunityProject(c, c.Param("id")); err != nil {
		return err
	}
	rows, err := database.New(h.db).ListCommunityMeasurements(c.Request().Context(), database.ListCommunityMeasurementsParams{ProjectID: c.Param("id"), UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	items := make([]wire.CommunityMeasurement, 0, len(rows))
	for _, row := range rows {
		items = append(items, sharedMeasurementView(database.GetCommunityMeasurementRow(row)))
	}
	return c.JSON(http.StatusOK, items)
}
func (h *Handler) ShareCommunityMeasurement(c echo.Context) error {
	if _, err := h.requireCommunityProject(c, c.Param("id")); err != nil {
		return err
	}
	var input struct {
		MeasurementID      string `json:"measurement_id"`
		ExperimentID       string `json:"experiment_id,omitempty"`
		ExperimentRevision *int64 `json:"experiment_revision,omitempty"`
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 4096)
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return err
	}
	if input.MeasurementID == "" || len(input.MeasurementID) > 256 || (input.ExperimentID == "") != (input.ExperimentRevision == nil) || (input.ExperimentRevision != nil && *input.ExperimentRevision < 1) {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "measurement_id and a complete optional experiment revision reference are required")
	}
	revision := sql.NullInt64{}
	if input.ExperimentRevision != nil {
		revision = sql.NullInt64{Int64: *input.ExperimentRevision, Valid: true}
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return communityFailure(err)
	}
	defer tx.Rollback()
	if err := pruneUnadmittedCommunityShares(ctx, tx, c.Param("id")); err != nil {
		return communityFailure(err)
	}
	q := database.New(tx)
	account := requestCaller(c)
	n, err := q.ShareCommunityMeasurement(ctx, database.ShareCommunityMeasurementParams{ProjectID: c.Param("id"), MeasurementID: input.MeasurementID, SharedAt: time.Now().Unix(), UserUuid: account.UserUUID, ExperimentID: sql.NullString{String: input.ExperimentID, Valid: input.ExperimentID != ""}, ExperimentRevision: revision})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		return communityNotFound()
	}
	row, err := q.GetCommunityMeasurement(ctx, database.GetCommunityMeasurementParams{ProjectID: c.Param("id"), MeasurementID: input.MeasurementID, UserUuid: account.UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if err := tx.Commit(); err != nil {
		return communityFailure(err)
	}
	return c.JSON(http.StatusCreated, sharedMeasurementView(row))
}
func (h *Handler) UnshareCommunityMeasurement(c echo.Context) error {
	if _, err := h.requireCommunityProject(c, c.Param("id")); err != nil {
		return err
	}
	ctx := c.Request().Context()
	q := database.New(h.db)
	n, err := q.UnshareCommunityMeasurement(ctx, database.UnshareCommunityMeasurementParams{ProjectID: c.Param("id"), MeasurementID: c.Param("measurement_id"), UserUuid: requestCaller(c).UserUUID})
	if err != nil {
		return communityFailure(err)
	}
	if n != 1 {
		funded, err := q.IsFundedCommunityMeasurement(ctx, database.IsFundedCommunityMeasurementParams{
			ProjectID: c.Param("id"), MeasurementID: c.Param("measurement_id"), UserUuid: requestCaller(c).UserUUID,
		})
		if err != nil {
			return communityFailure(err)
		}
		if funded {
			return communityConflict("Measurements funded by a community remain in its project history.")
		}
		return communityNotFound()
	}
	return c.NoContent(http.StatusNoContent)
}
