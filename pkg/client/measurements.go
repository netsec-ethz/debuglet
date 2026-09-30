// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

type ProfileConfig = wire.ProfileConfig
type Profile = wire.Profile
type ProfileSummary = wire.ProfileSummary
type MeasurementTemplate = wire.MeasurementTemplate

func (c *Client) MeasurementTemplates(ctx context.Context) ([]MeasurementTemplate, error) {
	var items []MeasurementTemplate
	err := c.measurementDocument(ctx, http.MethodGet, "measurement-templates", nil, http.StatusOK, &items)
	return items, err
}

func (c *Client) Profiles(ctx context.Context) ([]ProfileSummary, error) {
	var items []ProfileSummary
	err := c.measurementDocument(ctx, http.MethodGet, "measurement-profiles", nil, http.StatusOK, &items)
	return items, err
}

func (c *Client) Profile(ctx context.Context, id string) (Profile, error) {
	if err := validateJobID(id); err != nil {
		return Profile{}, err
	}
	var profile Profile
	err := c.measurementDocument(ctx, http.MethodGet, "measurement-profiles/"+id, nil, http.StatusOK, &profile)
	return profile, err
}

func (c *Client) SaveProfile(ctx context.Context, id string, config ProfileConfig) (Profile, error) {
	method, route, status := http.MethodPost, "measurement-profiles", http.StatusCreated
	if id != "" {
		if err := validateJobID(id); err != nil {
			return Profile{}, err
		}
		method, route, status = http.MethodPut, route+"/"+id, http.StatusOK
	}
	var profile Profile
	err := c.measurementDocument(ctx, method, route, config, status, &profile)
	return profile, err
}

func (c *Client) DeleteProfile(ctx context.Context, id string) error {
	if err := validateJobID(id); err != nil {
		return err
	}
	return c.measurementDocument(ctx, http.MethodDelete, "measurement-profiles/"+id, nil, http.StatusNoContent, nil)
}

func (c *Client) measurementDocument(ctx context.Context, method, route string, body any, status int, result any) error {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return err
		}
		if len(encoded) > wire.MaxProfileBytes {
			return c.protocolErr(method, route, "profile exceeds 8 MiB")
		}
	}
	data, err := c.doWithLimit(ctx, method, route, nil, encoded, status, wire.MaxProfileBytes+1024)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	return c.decode(method, route, data, result)
}
