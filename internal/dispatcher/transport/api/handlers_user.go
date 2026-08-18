package api

import (
	"database/sql"
	"debuglet/internal/dispatcher/database"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

/*
 * ████▄  ▄████▄ ███  ██  ▄████  ██████ █████▄
 * ██  ██ ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██▄▄██▄
 * ████▀  ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██   ██
 * ————————————————————————————————————————————
 *
 * The user system is currently insecure and extremely basic.
 * It only exists for local demo purposes.
 *
 * There is no proper authentication flow and users can simply be
 * fetched by their UUID, which shouldn't be possible later.
 *
 * TODO: Add proper authentication to these endpoints.
 *
 * ————————————————————————————————————————————
 * ████▄  ▄████▄ ███  ██  ▄████  ██████ █████▄
 * ██  ██ ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██▄▄██▄
 * ████▀  ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██   ██
 */

// GET /user/:id
func (h *Handler) GetUser(c echo.Context) error {
	userID := c.Param("id")
	if strings.TrimSpace(userID) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing user ID")
	}
	id, err := uuid.Parse(userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user ID")
	}

	queries := database.New(h.dispatcher.DB())
	user, err := queries.GetUserByUUID(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "user does not exist")
		}

		h.logger.Warn("Failed to fetch user", zap.String("uuid", id.String()), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to retrieve user")
	}

	return c.JSON(http.StatusOK, UserResponse{
		ID:   user.Uuid.String(),
		Name: user.Name,
	})
}

// GET /user-ids
func (h *Handler) ListUserIDs(c echo.Context) error {
	queries := database.New(h.dispatcher.DB())
	uuids, err := queries.ListUserUUIDs(c.Request().Context())
	if err != nil {
		h.logger.Warn("Failed to fetch user IDs", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to retrieve user IDs")
	}

	ids := make([]string, len(uuids))
	for i, u := range uuids {
		ids[i] = u.String()
	}
	return c.JSON(http.StatusOK, ids)
}

// PUT /user
func (h *Handler) CreateUser(c echo.Context) error {
	var req CreateUserRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}
	if strings.TrimSpace(req.Name) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing user name")
	}

	newUUID := uuid.New()
	queries := database.New(h.dispatcher.DB())
	user, err := queries.CreateUser(c.Request().Context(), database.CreateUserParams{
		Uuid: newUUID,
		Name: req.Name,
	})
	if err != nil {
		h.logger.Warn("Failed to create user", zap.String("uuid", newUUID.String()), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create user")
	}

	return c.JSON(http.StatusOK, UserResponse{
		ID:   user.Uuid.String(),
		Name: user.Name,
	})
}
