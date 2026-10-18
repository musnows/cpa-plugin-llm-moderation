package moderation

import (
	"encoding/json"
	"errors"
	"strings"
)

var ErrUnsupported = errors.New("unsupported_protocol")

func ExtractUserTexts(format string, raw []byte) ([]string, error) {
	if len(raw) > MaxRequestBytes {
		return nil, errors.New("input_too_large")
	}
	var root map[string]json.RawMessage
	if err := DecodeJSON(raw, &root); err != nil || root == nil {
		return nil, errors.New("invalid_request_json")
	}
	var texts []string
	var err error
	switch format {
	case "openai", "claude":
		texts, err = extractMessages(root["messages"])
	case "openai-response", "responses", "codex":
		input, ok := root["input"]
		if !ok {
			return nil, errors.New("missing_input")
		}
		var value string
		if json.Unmarshal(input, &value) == nil {
			texts = append(texts, value)
		} else {
			texts, err = extractMessages(input)
		}
	case "gemini", "gemini-cli":
		if format == "gemini-cli" && root["request"] != nil {
			if json.Unmarshal(root["request"], &root) != nil {
				return nil, errors.New("invalid_gemini_request")
			}
		}
		texts, err = extractGemini(root["contents"])
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(texts))
	total := 0
	for _, text := range texts {
		if strings.TrimSpace(text) != "" {
			total += len(text)
			if total > MaxInputBytes {
				return nil, errors.New("input_too_large")
			}
			out = append(out, text)
		}
	}
	return out, nil
}

func extractMessages(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("missing_messages")
	}
	var messages []map[string]json.RawMessage
	if json.Unmarshal(raw, &messages) != nil {
		return nil, errors.New("invalid_messages")
	}
	var out []string
	for _, message := range messages {
		var role, kind string
		if r := message["role"]; r != nil && json.Unmarshal(r, &role) != nil {
			return nil, errors.New("invalid_message_role")
		}
		if r := message["type"]; r != nil && json.Unmarshal(r, &kind) != nil {
			return nil, errors.New("invalid_message_type")
		}
		if role != "user" {
			continue
		}
		texts, err := extractContent(message["content"])
		if err != nil {
			return nil, err
		}
		out = append(out, texts...)
	}
	return out, nil
}

func extractContent(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("missing_user_content")
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return []string{text}, nil
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil {
		return nil, errors.New("invalid_user_content")
	}
	var out []string
	for _, block := range blocks {
		var kind string
		if json.Unmarshal(block["type"], &kind) != nil {
			return nil, errors.New("invalid_content_block")
		}
		switch kind {
		case "text", "input_text":
			if json.Unmarshal(block["text"], &text) != nil {
				return nil, errors.New("invalid_text_block")
			}
			out = append(out, text)
		case "image", "image_url", "input_image", "audio", "input_audio", "file", "input_file", "document", "tool_result", "tool_use", "function_call_output":
		default:
			return nil, errors.New("unknown_user_content_block")
		}
	}
	return out, nil
}

func extractGemini(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("missing_contents")
	}
	var contents []struct {
		Role  string                       `json:"role"`
		Parts []map[string]json.RawMessage `json:"parts"`
	}
	if json.Unmarshal(raw, &contents) != nil {
		return nil, errors.New("invalid_contents")
	}
	var out []string
	for _, content := range contents {
		if content.Role != "" && content.Role != "user" {
			continue
		}
		for _, part := range content.Parts {
			if raw, ok := part["text"]; ok {
				var text string
				if json.Unmarshal(raw, &text) != nil {
					return nil, errors.New("invalid_gemini_text")
				}
				out = append(out, text)
			} else if part["functionResponse"] == nil && part["functionCall"] == nil && part["inlineData"] == nil && part["fileData"] == nil && part["inline_data"] == nil && part["file_data"] == nil {
				return nil, errors.New("unknown_gemini_part")
			}
		}
	}
	return out, nil
}
