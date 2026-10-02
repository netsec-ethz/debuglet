// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

type RunDetail = wire.RunDetail
type Measurement = wire.Measurement
type MeasurementPage = wire.MeasurementPage

type MeasurementOptions struct {
	State, Search string
	Limit, Offset int64
}

func (c *Client) RunDetail(ctx context.Context, id string) (RunDetail, error) {
	if err := validateJobID(id); err != nil {
		return RunDetail{}, err
	}
	var doc RunDetail
	route := "debuglet/" + id + "/detail"
	data, err := c.doWithLimit(ctx, http.MethodGet, route, nil, nil, http.StatusOK, wire.MaxRunDetailBytes)
	if err != nil {
		return doc, err
	}
	err = c.decode(http.MethodGet, route, data, &doc)
	if err == nil && doc.RunID != id {
		err = c.protocolErr(http.MethodGet, "debuglet/"+id+"/detail", "detail belongs to another run")
	}
	return doc, err
}

// Measurement returns the first page of a measurement's children.
func (c *Client) Measurement(ctx context.Context, id string) (Measurement, error) {
	return c.MeasurementRuns(ctx, id, 25, 0)
}

// MeasurementRuns pages bounded references; use RunDetail for a child's config.
func (c *Client) MeasurementRuns(ctx context.Context, id string, limit, offset int64) (Measurement, error) {
	route := "measurements/" + url.PathEscape(id)
	query := url.Values{"limit": {strconv.FormatInt(limit, 10)}, "offset": {strconv.FormatInt(offset, 10)}}
	data, err := c.doWithLimit(ctx, http.MethodGet, route, query, nil, http.StatusOK, 1<<20)
	if err != nil {
		return Measurement{}, err
	}
	var doc Measurement
	if err := c.decode(http.MethodGet, route, data, &doc); err != nil {
		return doc, err
	}
	if doc.ID != id || doc.Limit != limit || doc.Offset != offset || doc.Total < 0 || int64(len(doc.Runs)) > limit {
		return Measurement{}, c.protocolErr(http.MethodGet, route, "inconsistent measurement page")
	}
	return doc, nil
}

func (c *Client) Measurements(ctx context.Context, opts MeasurementOptions) (MeasurementPage, error) {
	query := url.Values{"state": {opts.State}, "search": {opts.Search}, "offset": {strconv.FormatInt(opts.Offset, 10)}}
	if opts.Limit != 0 {
		query.Set("limit", strconv.FormatInt(opts.Limit, 10))
	}
	data, err := c.do(ctx, http.MethodGet, "measurements", query, nil, http.StatusOK)
	if err != nil {
		return MeasurementPage{}, err
	}
	var doc MeasurementPage
	err = c.decode(http.MethodGet, "measurements", data, &doc)
	return doc, err
}
