// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"go.uber.org/zap"
)

// RequestLog logs the matched route, never a raw URL, query, credential or
// body. Caller-supplied request IDs are not trusted as correlation identifiers.
func RequestLog(logger *zap.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			id := uuid.New()
			c.SetRequest(c.Request().WithContext(daemonlog.WithRequestID(c.Request().Context(), id)))
			c.Response().Header().Set(echo.HeaderXRequestID, id.String())
			if err := next(c); err != nil {
				c.Error(err)
			}
			logger.Info("HTTP request completed",
				zap.String("request_id", id.String()),
				zap.String("method", daemonlog.Identifier(c.Request().Method)),
				zap.String("route", daemonlog.Identifier(c.Path())),
				zap.Int("status", c.Response().Status), zap.Duration("latency", time.Since(start)))
			return nil
		}
	}
}
