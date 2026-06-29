package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	inlineImageDataURLPattern = regexp.MustCompile(`data:image/(?:jpeg|png|webp);base64,([A-Za-z0-9+/]+={0,2})`)
	errInvalidInlineImage     = errors.New("invalid inline image")
)

func (s *Server) replaceInlineStateMedia(ctx context.Context, userID string, value any) (any, bool, error) {
	switch v := value.(type) {
	case string:
		return s.replaceInlineMediaInString(ctx, userID, v)
	case []any:
		changed := false
		for i, item := range v {
			next, itemChanged, err := s.replaceInlineStateMedia(ctx, userID, item)
			if err != nil {
				return nil, false, err
			}
			if itemChanged {
				v[i] = next
				changed = true
			}
		}
		return v, changed, nil
	case map[string]any:
		changed := false
		for key, item := range v {
			next, itemChanged, err := s.replaceInlineStateMedia(ctx, userID, item)
			if err != nil {
				return nil, false, err
			}
			if itemChanged {
				v[key] = next
				changed = true
			}
		}
		return v, changed, nil
	default:
		return value, false, nil
	}
}

func (s *Server) replaceInlineMediaInString(ctx context.Context, userID, value string) (string, bool, error) {
	matches := inlineImageDataURLPattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value, false, nil
	}

	var out strings.Builder
	out.Grow(len(value))
	last := 0
	for _, match := range matches {
		out.WriteString(value[last:match[0]])
		raw := value[match[2]:match[3]]
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", false, fmt.Errorf("%w: %v", errInvalidInlineImage, err)
		}
		meta, err := s.saveMediaBytes(ctx, userID, decoded)
		if err != nil {
			return "", false, err
		}
		out.WriteString(s.mediaURL(meta.ID))
		last = match[1]
	}
	out.WriteString(value[last:])
	return out.String(), true, nil
}

func (s *Server) mediaURL(id string) string {
	prefix := strings.TrimRight(s.cfg.MediaURLPrefix, "/")
	if prefix == "" {
		prefix = "/api/media"
	}
	return prefix + "/" + id
}
