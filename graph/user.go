package graph

import (
	"context"
	"fmt"
	"strings"
)

type userCache struct {
	cache map[string]string // UPN -> ObjectID
}

var uc = &userCache{cache: make(map[string]string)}

// ResolveUserID converts UPN to object ID. Returns ID if already a GUID.
func (g *GraphHelper) ResolveUserID(upnOrID string) (string, error) {
	upnOrID = strings.TrimSpace(upnOrID)

	// If it looks like a GUID already, return it
	if isGUID(upnOrID) {
		return upnOrID, nil
	}

	// Check cache
	if id, ok := uc.cache[upnOrID]; ok {
		return id, nil
	}

	// Look up via Graph
	resp, err := g.appClient.Users().ByUserId(upnOrID).Get(context.Background(), nil)
	if err != nil {
		return "", fmt.Errorf("user not found: %s", upnOrID)
	}

	id := resp.GetId()
	if id == nil || strings.TrimSpace(*id) == "" {
		return "", fmt.Errorf("user has no object ID: %s", upnOrID)
	}

	// Cache it
	uc.cache[upnOrID] = *id
	return *id, nil
}

func isGUID(s string) bool {
	// Simple GUID check: 36 chars with hyphens at positions 8,13,18,23
	if len(s) != 36 {
		return false
	}
	guidPattern := []int{8, 13, 18, 23}
	for _, pos := range guidPattern {
		if s[pos] != '-' {
			return false
		}
	}
	return true
}
