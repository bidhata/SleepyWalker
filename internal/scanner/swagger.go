package scanner

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// SwaggerDiscover fetches and parses an OpenAPI/Swagger spec URL, then generates
// entry points for all discovered API endpoints with their parameters.
func SwaggerDiscover(specURL, targetBaseURL string) ([]EntryPoint, error) {
	log.Printf("[SWAGGER] Loading OpenAPI spec from %s", specURL)

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	doc, err := loader.LoadFromURI(mustParseURL(specURL))
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI spec: %w", err)
	}

	if err := doc.Validate(context.Background()); err != nil {
		// Many real-world specs have minor validation issues — log and continue.
		log.Printf("[SWAGGER] Warning: spec validation issues: %v", err)
	}

	// Determine base URL from spec servers or fall back to provided target.
	baseURL := targetBaseURL
	if len(doc.Servers) > 0 && doc.Servers[0].URL != "" {
		serverURL := doc.Servers[0].URL
		if strings.HasPrefix(serverURL, "http") {
			baseURL = strings.TrimRight(serverURL, "/")
		}
	}
	baseURL = strings.TrimRight(baseURL, "/")

	var eps []EntryPoint

	for path, pathItem := range doc.Paths.Map() {
		operations := map[string]*openapi3.Operation{
			"GET":    pathItem.Get,
			"POST":   pathItem.Post,
			"PUT":    pathItem.Put,
			"PATCH":  pathItem.Patch,
			"DELETE": pathItem.Delete,
		}

		for method, op := range operations {
			if op == nil {
				continue
			}

			fullURL := baseURL + path
			params := extractOpenAPIParams(op, pathItem.Parameters)

			// Determine injection location from method and request body.
			loc := "query"
			if method == "POST" || method == "PUT" || method == "PATCH" {
				if op.RequestBody != nil {
					loc = "json"
				} else {
					loc = "body"
				}
			}

			// Replace path parameters with test values in URL.
			// Fix #9: only switch loc to "query" when the endpoint has no body —
			// a POST with both a path param and a JSON body should keep loc="json".
			for paramName := range params {
				placeholder := "{" + paramName + "}"
				if strings.Contains(fullURL, placeholder) {
					fullURL = strings.ReplaceAll(fullURL, placeholder, "1")
					if loc != "json" && loc != "body" {
						loc = "query"
					}
				}
			}

			if len(params) == 0 {
				params = map[string]string{"id": "1"}
			}

			eps = append(eps, EntryPoint{
				Method:       method,
				URL:          fullURL,
				Params:       params,
				InjectionLoc: loc,
			})
		}
	}

	eps = deduplicateEPs(eps)
	log.Printf("[SWAGGER] Discovered %d endpoint(s) from OpenAPI spec", len(eps))
	return eps, nil
}

// extractOpenAPIParams extracts parameter names from an operation and path-level params.
func extractOpenAPIParams(op *openapi3.Operation, pathParams openapi3.Parameters) map[string]string {
	params := make(map[string]string)

	for _, ref := range pathParams {
		if ref.Value != nil {
			params[ref.Value.Name] = exampleValue(ref.Value)
		}
	}

	for _, ref := range op.Parameters {
		if ref.Value != nil {
			params[ref.Value.Name] = exampleValue(ref.Value)
		}
	}

	if op.RequestBody != nil && op.RequestBody.Value != nil {
		for _, content := range op.RequestBody.Value.Content {
			if content.Schema != nil && content.Schema.Value != nil {
				for propName, prop := range content.Schema.Value.Properties {
					val := ""
					if prop.Value != nil && prop.Value.Example != nil {
						val = fmt.Sprintf("%v", prop.Value.Example)
					}
					params[propName] = val
				}
			}
		}
	}

	return params
}

// exampleValue extracts a sensible test value from a parameter definition.
func exampleValue(param *openapi3.Parameter) string {
	if param.Example != nil {
		return fmt.Sprintf("%v", param.Example)
	}
	if param.Schema != nil && param.Schema.Value != nil {
		types := param.Schema.Value.Type.Slice()
		if len(types) > 0 {
			switch types[0] {
			case "integer", "number":
				return "1"
			case "boolean":
				return "true"
			default:
				return "test"
			}
		}
	}
	return ""
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		return &url.URL{}
	}
	return u
}
