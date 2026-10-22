// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

const maxTemplateBytes = 4 << 20

func (h *Handler) registerTemplateRoutes(e *echo.Echo) {
	e.GET("/templates", h.ListTemplates)
	e.POST("/templates", h.CreateTemplate)
	e.GET("/templates/:id", h.GetTemplate)
	e.PUT("/templates/:id", h.UpdateTemplate)
	e.DELETE("/templates/:id", h.DeleteTemplate)
}

func templateFailure(err error) error {
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read or save template", err)
}

func templateNotFound() error {
	return apiError(http.StatusNotFound, CodeNotFound, "template not found")
}

func (h *Handler) ListTemplates(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	rows, err := h.db.QueryContext(c.Request().Context(), `SELECT id,name,description,collection,kind,revision,updated_at
 FROM personal_templates WHERE user_id=(SELECT id FROM users WHERE uuid=?) ORDER BY updated_at DESC,id`, account.UserUUID)
	if err != nil {
		return templateFailure(err)
	}
	defer rows.Close()
	items := make([]wire.Template, 0)
	for rows.Next() {
		var item wire.Template
		var timestamp int64
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Collection, &item.Kind, &item.Revision, &timestamp); err != nil {
			return templateFailure(err)
		}
		item.UpdatedAt = time.Unix(timestamp, 0).UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return templateFailure(err)
	}
	return c.JSON(http.StatusOK, items)
}

func (h *Handler) readTemplate(c echo.Context, id string) (wire.Template, error) {
	account, err := requireAccount(c)
	if err != nil {
		return wire.Template{}, err
	}
	var item wire.Template
	var timestamp int64
	var document string
	err = h.db.QueryRowContext(c.Request().Context(), `SELECT id,name,description,collection,kind,document,revision,updated_at
 FROM personal_templates WHERE id=? AND user_id=(SELECT id FROM users WHERE uuid=?)`, id, account.UserUUID).
		Scan(&item.ID, &item.Name, &item.Description, &item.Collection, &item.Kind, &document, &item.Revision, &timestamp)
	if errors.Is(err, sql.ErrNoRows) {
		return item, templateNotFound()
	}
	if err != nil {
		return item, templateFailure(err)
	}
	item.Document, item.UpdatedAt = json.RawMessage(document), time.Unix(timestamp, 0).UTC()
	return item, nil
}

func (h *Handler) GetTemplate(c echo.Context) error {
	item, err := h.readTemplate(c, c.Param("id"))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, item)
}

type templateInput struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Collection  string          `json:"collection,omitempty"`
	Kind        string          `json:"kind"`
	Document    json.RawMessage `json:"document"`
	Revision    int64           `json:"revision,omitempty"`
}

func readTemplateInput(c echo.Context) (templateInput, error) {
	var input templateInput
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxTemplateBytes)
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return input, err
	}
	input.Name, input.Collection = strings.TrimSpace(input.Name), strings.TrimSpace(input.Collection)
	if input.Name == "" || len(input.Name) > 120 || len(input.Description) > 4000 || len(input.Collection) > 120 {
		return input, apiError(http.StatusBadRequest, CodeInvalidRequest, "template name and collection are limited to 120 bytes and description to 4000 bytes")
	}
	var err error
	input.Document, _, err = validateCommunityDocument(input.Kind, input.Document, nil)
	if err != nil {
		return input, err
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return input, templateFailure(err)
	}
	if len(encoded) > maxTemplateBytes {
		return input, apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "template source exceeds 4 MiB")
	}
	return input, nil
}

func (h *Handler) CreateTemplate(c echo.Context) error { return h.saveTemplate(c, true) }
func (h *Handler) UpdateTemplate(c echo.Context) error { return h.saveTemplate(c, false) }

func (h *Handler) saveTemplate(c echo.Context, create bool) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if !create {
		if _, err := h.readTemplate(c, c.Param("id")); err != nil {
			return err
		}
	}
	input, err := readTemplateInput(c)
	if err != nil {
		return err
	}
	if create && input.Revision != 0 || !create && (input.Revision < 1 || input.Revision >= 1<<53-1) {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "new templates omit revision; updates require the current positive revision")
	}
	item := wire.Template{ID: c.Param("id"), Name: input.Name, Description: input.Description, Collection: input.Collection,
		Kind: input.Kind, Document: input.Document, Revision: input.Revision + 1, UpdatedAt: time.Unix(time.Now().Unix(), 0).UTC()}
	var result sql.Result
	// Conditional writes enforce quota and revision checks atomically, including
	// concurrent saves. Updating a template replaces only that personal copy.
	if create {
		item.ID = uuid.NewString()
		result, err = h.db.ExecContext(c.Request().Context(), `INSERT INTO personal_templates(id,user_id,name,description,collection,kind,document,revision,updated_at)
 SELECT ?,u.id,?,?,?,?,?,1,? FROM users u WHERE u.uuid=?
 AND (SELECT count(*) FROM personal_templates WHERE user_id=u.id)<256
 AND (SELECT coalesce(sum(length(CAST(document AS BLOB))),0) FROM personal_templates WHERE user_id=u.id)+?<=67108864`,
			item.ID, item.Name, item.Description, item.Collection, item.Kind, string(item.Document), item.UpdatedAt.Unix(), account.UserUUID, len(item.Document))
	} else {
		result, err = h.db.ExecContext(c.Request().Context(), `UPDATE personal_templates SET name=?,description=?,collection=?,kind=?,document=?,revision=revision+1,updated_at=?
 WHERE id=? AND revision=? AND user_id=(SELECT id FROM users WHERE uuid=?)
 AND (SELECT coalesce(sum(length(CAST(document AS BLOB))),0) FROM personal_templates other WHERE other.user_id=personal_templates.user_id AND other.id!=personal_templates.id)+?<=67108864`,
			item.Name, item.Description, item.Collection, item.Kind, string(item.Document), item.UpdatedAt.Unix(), item.ID, input.Revision, account.UserUUID, len(item.Document))
	}
	if err != nil {
		return templateFailure(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return templateFailure(err)
	}
	if n != 1 {
		return apiError(http.StatusConflict, CodeInvalidRequest, "template changed or the personal library limit (256 templates, 64 MiB source) was reached; refresh or remove an unused template")
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	return c.JSON(status, item)
}

func (h *Handler) DeleteTemplate(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	result, err := h.db.ExecContext(c.Request().Context(), `DELETE FROM personal_templates WHERE id=? AND user_id=(SELECT id FROM users WHERE uuid=?)`, c.Param("id"), account.UserUUID)
	if err != nil {
		return templateFailure(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return templateFailure(err)
	}
	if n != 1 {
		return templateNotFound()
	}
	return c.NoContent(http.StatusNoContent)
}
