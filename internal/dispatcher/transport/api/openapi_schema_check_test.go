package api

import (
	"net/http"
	"strings"
	"testing"
)

// These tests pin the schema subset the loader in openapi_schema_test.go
// accepts. They work on small documents of their own: the tracked contract is
// loaded by the suite in openapi_contract_test.go, while a constraint the value
// checks do not implement has to be rejected here whether or not any payload
// ever reaches it.

// scDocument builds the smallest document newContract accepts, splicing in one
// operation body and one components.schemas body. Both are written without
// leading indentation.
func scDocument(operation, schemas string) []byte {
	return []byte(`openapi: "3.0.3"
info:
  title: "Fragment"
  version: "1.3"
paths:
  /thing:
    get:
` + scIndent(operation, "      ") + `components:
  schemas:
` + scIndent(schemas, "    "))
}

// scIndent indents one block and drops its blank lines.
func scIndent(block, prefix string) string {
	var b strings.Builder
	for _, line := range strings.Split(block, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// scUnchecked assembles a contract the way the loader did before it checked the
// schema subset, so a case can show what the value checks accept on their own.
func scUnchecked(t *testing.T, document []byte) *contract {
	t.Helper()
	value, err := parseYAML(document)
	if err != nil {
		t.Fatalf("parse the case document: %v", err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("the case document is not a mapping")
	}
	paths, _ := root["paths"].(map[string]any)
	components, _ := root["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	if paths == nil || schemas == nil {
		t.Fatal("the case document has no paths or components.schemas mapping")
	}
	return &contract{root: root, paths: paths, schemas: schemas}
}

// scResponseBody returns the documented 200 JSON body schema of the case
// operation.
func scResponseBody(t *testing.T, c *contract) any {
	t.Helper()
	operation, _, err := c.operation(http.MethodGet, "/thing")
	if err != nil {
		t.Fatalf("GET /thing: %v", err)
	}
	schema, documented, hasBody := responseSchema(operation, http.StatusOK)
	if !documented || !hasBody || schema == nil {
		t.Fatal("the case documents no JSON body for 200")
	}
	return schema
}

// scThingResponse answers with the Thing schema, so a case whose schema under
// test sits in components.schemas needs no operation of its own.
const scThingResponse = `responses:
  "200":
    content:
      application/json:
        schema:
          $ref: "#/components/schemas/Thing"`

// scStringThing is the smallest components.schemas body a document needs.
const scStringThing = `
Thing:
  type: string`

// The operations below declare a schema in each of the other positions the
// document may put one: a parameter, a request body, a response body and a
// response header.
const scParameterOperation = `parameters:
  - name: "limit"
    in: "query"
    required: false
    schema:
      type: integer
      exclusiveMinimum: 1
responses:
  "200":
    content:
      application/json:
        schema:
          $ref: "#/components/schemas/Thing"`

const scRequestOperation = `requestBody:
  content:
    application/json:
      schema:
        type: object
        additionalProperties: false
        minProperties: 1
        properties:
          name:
            type: string
responses:
  "200":
    content:
      application/json:
        schema:
          $ref: "#/components/schemas/Thing"`

const scResponseOperation = `responses:
  "200":
    content:
      application/json:
        schema:
          type: array
          uniqueItems: true
          items:
            type: string`

const scHeaderOperation = `responses:
  "200":
    headers:
      X-Thing:
        schema:
          type: string
          maxLength: 1
    content:
      application/json:
        schema:
          $ref: "#/components/schemas/Thing"`

// Shapes shared by several cases below.
const (
	scNameMinLength = `
Thing:
  type: object
  additionalProperties: false
  properties:
    name:
      type: string
      minLength: 8`

	scValuesMaxLength = `
Thing:
  type: object
  additionalProperties: false
  properties:
    values:
      type: array
      items:
        type: string
        maxLength: 2`
)

// TestSchemaSubsetCheckRejectsUnsupportedConstructs covers every position the
// walk visits and every way a schema can state something the value checks do
// not read. Each case must be reported with the keyword and the location,
// because a message that names neither cannot be acted on. Where a case has a
// body, the value checks alone accept that body against the same document:
// either they measure nothing for the keyword, or the body never reaches the
// schema that states it, so without the check the constraint would be
// documentation no exchange is ever held to.
func TestSchemaSubsetCheckRejectsUnsupportedConstructs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation string
		want      []string
		body      string
		schemas   string
	}{
		{
			name:      "an unknown keyword in a named schema",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", `"minLength"`},
			body:      `"x"`,
			schemas: `
Thing:
  type: string
  minLength: 4`,
		},
		{
			name:      "a length nothing measures on a nested property",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.name", `"minLength"`},
			body:      `{"name":"x"}`,
			schemas:   scNameMinLength,
		},
		{
			name:      "a constraint on an optional property the body omits",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.name", `"minLength"`},
			body:      `{}`,
			schemas:   scNameMinLength,
		},
		{
			name:      "a length nothing measures on the items of an array",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.values.items", `"maxLength"`},
			body:      `{"values":["000"]}`,
			schemas:   scValuesMaxLength,
		},
		{
			name:      "a constraint on the items of an empty array",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.values.items", `"maxLength"`},
			body:      `{"values":[]}`,
			schemas:   scValuesMaxLength,
		},
		{
			name:      "a constraint in the alternative that does not match",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.oneOf[1]", `"maxLength"`},
			body:      `3`,
			schemas: `
Thing:
  oneOf:
    - type: integer
    - type: string
      maxLength: 8`,
		},
		{
			name:      "a constraint behind a reference",
			operation: scThingResponse,
			want:      []string{"components.schemas.Inner", `"minLength"`},
			body:      `{"inner":"x"}`,
			schemas: `
Thing:
  type: object
  additionalProperties: false
  properties:
    inner:
      $ref: "#/components/schemas/Inner"
Inner:
  type: string
  minLength: 8`,
		},
		{
			name:      "a constraint behind a documented null",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.note", `"minLength"`},
			body:      `{"note":null}`,
			schemas: `
Thing:
  type: object
  additionalProperties: false
  properties:
    note:
      type: string
      nullable: true
      minLength: 8`,
		},
		{
			name:      "an exclusive bound nothing compares",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.count", `"exclusiveMinimum"`},
			body:      `{"count":0}`,
			schemas: `
Thing:
  type: object
  additionalProperties: false
  properties:
    count:
      type: integer
      exclusiveMinimum: 10`,
		},
		{
			name:      "a format nothing parses",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.when", `format date-time is not implemented for type "string"`},
			body:      `{"when":"not a timestamp"}`,
			schemas: `
Thing:
  type: object
  additionalProperties: false
  properties:
    when:
      type: string
      format: "date-time"`,
		},
		{
			name:      "an object whose additionalProperties is a schema",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", "additionalProperties is", "only a boolean is read"},
			body:      `{"name":"x","extra":{"nested":1}}`,
			schemas: `
Thing:
  type: object
  additionalProperties:
    type: string
  properties:
    name:
      type: string`,
		},
		{
			name:      "an unknown keyword in a query parameter schema",
			operation: scParameterOperation,
			want:      []string{"paths./thing.get.parameters.limit.schema", `"exclusiveMinimum"`},
			schemas:   scStringThing,
		},
		{
			name:      "an unknown keyword in a request body schema",
			operation: scRequestOperation,
			want:      []string{"paths./thing.get.requestBody.content.application/json.schema", `"minProperties"`},
			schemas:   scStringThing,
		},
		{
			name:      "an unknown keyword in a response body schema",
			operation: scResponseOperation,
			want:      []string{"paths./thing.get.responses.200.content.application/json.schema", `"uniqueItems"`},
			body:      `["a","a"]`,
			schemas:   scStringThing,
		},
		{
			name:      "an unknown keyword in a response header schema",
			operation: scHeaderOperation,
			want:      []string{"paths./thing.get.responses.200.headers.X-Thing.schema", `"maxLength"`},
			schemas:   scStringThing,
		},
		{
			name:      "a numeric bound beside a string",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", `"minimum" is read for type`, `not for type "string"`},
			body:      `"x"`,
			schemas: `
Thing:
  type: string
  minimum: 1`,
		},
		{
			name:      "an items schema beside an object",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", `"items" is read for type "array"`, `not for type "object"`},
			schemas: `
Thing:
  type: object
  additionalProperties: false
  items:
    type: string`,
		},
		{
			name:      "a format on a type whose check reads none",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", `"format" is read for type "integer" and "string"`},
			schemas: `
Thing:
  type: boolean
  format: "int64"`,
		},
		{
			name:      "an unimplemented type",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", `type "null" is not implemented`},
			schemas: `
Thing:
  type: "null"`,
		},
		{
			name:      "a schema that declares nothing to check",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", "declares no type, $ref or oneOf"},
			schemas: `
Thing:
  description: "Anything at all."`,
		},
		{
			name:      "an array without an items schema",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", "documents no items schema"},
			schemas: `
Thing:
  type: array
  nullable: true`,
		},
		{
			name:      "required that is not a sequence",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", "required is not a sequence of field names"},
			body:      `{}`,
			schemas: `
Thing:
  type: object
  additionalProperties: true
  required: "name"`,
		},
		{
			name:      "a keyword beside alternatives",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", `"type" is not read beside "oneOf"`},
			schemas: `
Thing:
  type: object
  oneOf:
    - type: integer
    - type: string`,
		},
		{
			name:      "a reference without a target",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.inner", `reference "#/components/schemas/Missing" has no target`},
			schemas: `
Thing:
  type: object
  additionalProperties: false
  properties:
    inner:
      $ref: "#/components/schemas/Missing"`,
		},
		{
			name:      "a pattern that does not compile",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing", "does not compile"},
			schemas: `
Thing:
  type: string
  pattern: "^[a-z$"`,
		},
		{
			name:      "a reference outside the schemas section",
			operation: scThingResponse,
			want:      []string{"components.schemas.Thing.properties.inner", `unsupported reference "#/components/responses/Thing"`},
			schemas: `
Thing:
  type: object
  additionalProperties: false
  properties:
    inner:
      $ref: "#/components/responses/Thing"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := scDocument(tc.operation, tc.schemas)
			_, err := newContract(document)
			if err == nil {
				t.Fatal("the loader accepted a construct no check reads")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the report does not state %s:\n%v", want, err)
				}
			}
			if tc.body == "" {
				return
			}
			c := scUnchecked(t, document)
			if problems := c.validateJSON(scResponseBody(t, c), []byte(tc.body), "GET /thing 200"); len(problems) != 0 {
				t.Fatalf("the value checks were expected to pass %s, they reported %v", tc.body, problems)
			}
		})
	}
}

const scSupportedOperation = `parameters:
  - name: "limit"
    in: "query"
    required: false
    description: "How many entries to return."
    schema:
      type: integer
      format: "int64"
      minimum: 1
      maximum: 100
requestBody:
  content:
    application/json:
      schema:
        $ref: "#/components/schemas/Thing"
responses:
  "200":
    description: "One thing."
    headers:
      X-Thing:
        description: "Says something about the thing."
        schema:
          type: string
    content:
      application/json:
        schema:
          $ref: "#/components/schemas/Thing"
  "204":
    description: "Nothing, so no body is documented."`

const scSupportedSchemas = `
Thing:
  type: object
  title: "Thing"
  description: "Every construct the checks implement."
  additionalProperties: false
  required:
    - name
  properties:
    name:
      type: string
      pattern: "^[a-z]+$"
      description: "A name."
      deprecated: false
    key:
      type: string
      format: "byte"
      nullable: true
    id:
      type: string
      format: "uuid"
    state:
      type: string
      enum:
        - "queued"
        - "done"
    count:
      type: integer
      format: "int64"
      minimum: 0
      maximum: 10
    ratio:
      type: number
      minimum: 0
      maximum: 1
    ready:
      type: boolean
    values:
      type: array
      nullable: true
      items:
        $ref: "#/components/schemas/Inner"
    choice:
      description: "One of two documented shapes."
      oneOf:
        - $ref: "#/components/schemas/Inner"
        - type: integer
Inner:
  type: object
  example: "an annotation, not an assertion"
  additionalProperties: false
  required:
    - text
  properties:
    text:
      type: string`

// TestSchemaSubsetCheckAcceptsTheImplementedSubset keeps the check from
// tightening past what the value checks read: a document that uses only
// implemented constructs must load, and its values must still be judged in both
// directions.
func TestSchemaSubsetCheckAcceptsTheImplementedSubset(t *testing.T) {
	c, err := newContract(scDocument(scSupportedOperation, scSupportedSchemas))
	if err != nil {
		t.Fatalf("the loader rejected the implemented subset: %v", err)
	}
	schema := scResponseBody(t, c)

	conforming := `{"name":"n","key":"YWI=","id":"11111111-1111-4111-8111-111111111111",` +
		`"state":"done","count":3,"ratio":0.5,"ready":true,"values":[{"text":"t"}],"choice":7}`
	if problems := c.validateJSON(schema, []byte(conforming), "GET /thing 200"); len(problems) != 0 {
		t.Errorf("a conforming body was reported: %v", problems)
	}
	for _, violation := range []struct {
		name string
		body string
	}{
		{name: "an undocumented value", body: `{"name":"n","state":"gone"}`},
		{name: "a missing required field", body: `{"state":"done"}`},
		{name: "an undocumented field", body: `{"name":"n","extra":1}`},
		{name: "a bound", body: `{"name":"n","count":11}`},
		{name: "a format", body: `{"name":"n","id":"not-a-uuid"}`},
		{name: "a pattern", body: `{"name":"N"}`},
		{name: "a null that is not documented", body: `{"name":null}`},
		{name: "an element of an array", body: `{"name":"n","values":[{"text":1}]}`},
		{name: "no matching alternative", body: `{"name":"n","choice":"neither"}`},
	} {
		if problems := c.validateJSON(schema, []byte(violation.body), "GET /thing 200"); len(problems) == 0 {
			t.Errorf("%s was accepted: %s", violation.name, violation.body)
		}
	}
}

// TestSchemaSubsetCheckAcceptsObjectsTheValidatorReads keeps two valid object
// shapes loading, because validateObject enforces them as written: an omitted
// additionalProperties means true, so an unknown field passes while documented
// properties are still checked, and a required name is enforced for presence
// whether or not a property schema describes it.
func TestSchemaSubsetCheckAcceptsObjectsTheValidatorReads(t *testing.T) {
	for _, tc := range []struct {
		name    string
		good    string
		bad     string
		schemas string
	}{
		{
			name: "an object that leaves additionalProperties implicit",
			good: `{"name":"ok","extra":1}`,
			bad:  `{"name":7}`,
			schemas: `
Thing:
  type: object
  properties:
    name:
      type: string`,
		},
		{
			name: "a required name without a property schema",
			good: `{"name":7}`,
			bad:  `{}`,
			schemas: `
Thing:
  type: object
  additionalProperties: true
  required:
    - name`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newContract(scDocument(scThingResponse, tc.schemas))
			if err != nil {
				t.Fatalf("the loader rejected a shape the value checks enforce: %v", err)
			}
			schema := scResponseBody(t, c)
			if problems := c.validateJSON(schema, []byte(tc.good), "GET /thing 200"); len(problems) != 0 {
				t.Errorf("%s was reported: %v", tc.good, problems)
			}
			if problems := c.validateJSON(schema, []byte(tc.bad), "GET /thing 200"); len(problems) == 0 {
				t.Errorf("%s was accepted", tc.bad)
			}
		})
	}
}

// TestSchemaSubsetCheckRejectsAResponseReference covers a response that is a
// reference to components.responses. responseSchema does not resolve it and
// reads it as a response without a body, so a schema behind it would never be
// checked, whatever it says. The check rejects the reference itself.
func TestSchemaSubsetCheckRejectsAResponseReference(t *testing.T) {
	document := append(scDocument(`responses:
  "200":
    $ref: "#/components/responses/Bad"`, scStringThing), scIndent(`responses:
  Bad:
    description: "A reply."
    content:
      application/json:
        schema:
          type: string
          minLength: 9`, "  ")...)
	if _, err := newContract(document); err == nil {
		t.Fatal("the loader accepted a response reference")
	} else if !strings.Contains(err.Error(), "paths./thing.get.responses.200: a response $ref is not resolved") {
		t.Fatalf("the report does not name the reference and its location:\n%v", err)
	}
	c := scUnchecked(t, document)
	operation, _, err := c.operation(http.MethodGet, "/thing")
	if err != nil {
		t.Fatalf("GET /thing: %v", err)
	}
	if schema, documented, hasBody := responseSchema(operation, http.StatusOK); !documented || hasBody || schema != nil {
		t.Fatalf("responseSchema = %v, %v, %v; want the reference read as a documented response without a body", schema, documented, hasBody)
	}
}

// TestKeywordsBesideAReferenceAreLost covers a keyword written beside a
// reference. OpenAPI 3.0.3 ignores the siblings of a Reference Object, and so
// does resolve, which answers from the target alone. An author who writes
// nullable there expects null to be accepted, but the value checks reject it,
// so the document misleads its reader. The check rejects the shape rather than
// leaving the document and the validator to disagree.
func TestKeywordsBesideAReferenceAreLost(t *testing.T) {
	document := scDocument(scThingResponse, `
Thing:
  type: object
  additionalProperties: false
  properties:
    inner:
      $ref: "#/components/schemas/Inner"
      nullable: true
Inner:
  type: string`)
	if _, err := newContract(document); err == nil {
		t.Fatal("the loader accepted a keyword beside a reference")
	} else if !strings.Contains(err.Error(), `components.schemas.Thing.properties.inner: "nullable" is not read beside "$ref"`) {
		t.Fatalf("the report does not state which keyword is lost and where:\n%v", err)
	}
	c := scUnchecked(t, document)
	problems := c.validateJSON(scResponseBody(t, c), []byte(`{"inner":null}`), "GET /thing 200")
	if len(problems) != 1 || !strings.Contains(problems[0], "does not allow null") {
		t.Fatalf("the value checks reported %v, want null rejected as the target alone says", problems)
	}
}
