package lxd

import (
	"context"
	"encoding/json"
	"fmt"
)

// Profile represents an LXD profile's metadata
type Profile struct {
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Config      map[string]string            `json:"config"`
	Devices     map[string]map[string]string `json:"devices"`
}

// GetProfile fetches a single profile by name
func (c *Client) GetProfile(ctx context.Context, name string) (*Profile, error) {
	resp, err := c.doGet(ctx, fmt.Sprintf("/1.0/profiles/%s", name))
	if err != nil {
		return nil, err
	}

	var p struct {
		Name        string                       `json:"name"`
		Description string                       `json:"description"`
		Config      map[string]string            `json:"config"`
		Devices     map[string]map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(resp.Metadata, &p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}

	return &Profile{
		Name:        p.Name,
		Description: p.Description,
		Config:      p.Config,
		Devices:     p.Devices,
	}, nil
}

// GetProfiles fetches multiple profiles by name. Returns a map name->Profile.
func (c *Client) GetProfiles(ctx context.Context, names []string) (map[string]*Profile, error) {
	out := make(map[string]*Profile)
	for _, n := range names {
		p, err := c.GetProfile(ctx, n)
		if err != nil {
			return nil, fmt.Errorf("get profile %s: %w", n, err)
		}
		out[n] = p
	}
	return out, nil
}
