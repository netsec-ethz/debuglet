package api

import (
	"database/sql"
	"debuglet/internal/dispatcher/database"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// InsecureAuthMiddleware is a middleware that checks for the presence of a "session_token" cookie in the request.
// If present, it is applied to the request context. If not present, the request is allowed to proceed without authentication.
func InsecureAuthMiddleware(db *sql.DB, logger *zap.Logger) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("session_token")
			if err != nil {
				return next(c)
			}
			id, err := uuid.Parse(cookie.Value)
			if err != nil {
				logger.Warn("invalid user cookie", zap.String("cookie_value", cookie.Value), zap.Error(err))
				return next(c)
			}

			queries := database.New(db)
			user, err := queries.GetUserByUUID(c.Request().Context(), id)
			if err != nil {
				logger.Warn("failed to get user from database", zap.String("user_id", id.String()), zap.Error(err))
				return next(c)
			}

			c.Set("user", user)
			return next(c)
		}
	}
}

func GetUser(c echo.Context) (database.User, bool) {
	user, ok := c.Get("user").(database.User)
	return user, ok
}
