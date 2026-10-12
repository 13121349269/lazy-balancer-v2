package mcpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestListToolSpecs_returns_sanitized_independent_copy(t *testing.T) {
	// Given
	first := ListToolSpecs()

	// When
	first[0].Name = "changed_by_caller"
	second := ListToolSpecs()
	encoded, err := json.Marshal(second)

	// Then
	if err != nil {
		t.Fatalf("marshal public tool specs: %v", err)
	}
	if len(second) != len(tools) {
		t.Fatalf("tool count=%d, want %d", len(second), len(tools))
	}
	if second[0].Name == "changed_by_caller" {
		t.Fatal("ListToolSpecs returned caller-mutable registry state")
	}
	if strings.Contains(string(encoded), "path_args") || strings.Contains(string(encoded), "query_args") {
		t.Fatalf("public registry leaks internal fields: %s", encoded)
	}
	for index, spec := range second {
		if spec.Name == "" || spec.Description == "" || spec.Method == "" || !strings.HasPrefix(spec.Path, "/api/v1/") {
			t.Fatalf("tool %d has incomplete public metadata: %+v", index, spec)
		}
		_, probe := ReadOnlyProbeTools[spec.Name]
		_, hidden := readOnlyHiddenTools[spec.Name]
		if wantReadOnly := (spec.Method == http.MethodGet && !hidden) || probe; spec.ReadOnly != wantReadOnly {
			t.Fatalf("tool %s read_only=%v method=%s probe=%v hidden=%v, want %v", spec.Name, spec.ReadOnly, spec.Method, probe, hidden, wantReadOnly)
		}
		if len(spec.InputSchema) > 0 {
			var shape map[string]any
			if err := json.Unmarshal(spec.InputSchema, &shape); err != nil || shape["type"] != "object" {
				t.Fatalf("tool %s input_schema is not a valid JSON schema object: %s", spec.Name, spec.InputSchema)
			}
		}
	}
}
