package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// The YAML decoder handles syntax; this adapter rejects ambiguous object keys
// and YAML-specific indirection. The schema checker below deliberately accepts
// only the OpenAPI keywords it actually validates. Request and response bodies
// and query parameter names are checked; parameter/header values are not.

func parseYAML(data []byte) (any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("contract must contain one YAML document")
	}
	return contractYAMLValue(&document)
}

func contractYAMLValue(node *yaml.Node) (any, error) {
	if node.Anchor != "" || node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
		return nil, fmt.Errorf("line %d: anchors, aliases and explicit tags are not supported", node.Line)
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return nil, fmt.Errorf("expected one YAML value")
		}
		return contractYAMLValue(node.Content[0])
	case yaml.MappingNode:
		mapping := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Anchor != "" || key.Style&yaml.TaggedStyle != 0 || key.Tag == "!!merge" {
				return nil, fmt.Errorf("line %d: mapping keys must be plain or quoted scalar names", key.Line)
			}
			if _, exists := mapping[key.Value]; exists {
				return nil, fmt.Errorf("line %d: duplicate key %q", key.Line, key.Value)
			}
			value, err := contractYAMLValue(node.Content[i+1])
			if err != nil {
				return nil, err
			}
			mapping[key.Value] = value
		}
		return mapping, nil
	case yaml.SequenceNode:
		items := make([]any, 0, len(node.Content))
		for _, item := range node.Content {
			value, err := contractYAMLValue(item)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		return items, nil
	case yaml.ScalarNode:
		if node.Style != 0 {
			return node.Value, nil
		}
		// Preserve the contract's JSON-like scalar types. YAML's implicit
		// timestamps, octal integers and case-insensitive booleans do not apply.
		switch node.Value {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "", "null", "~":
			return nil, nil
		}
		if n, err := strconv.ParseInt(node.Value, 10, 64); err == nil {
			return n, nil
		}
		if n, err := strconv.ParseFloat(node.Value, 64); err == nil {
			return n, nil
		}
		return node.Value, nil
	default:
		return nil, fmt.Errorf("line %d: unsupported YAML value", node.Line)
	}
}

// --------------------------------------------------------------- OpenAPI view

// contract is a parsed api/openapi.yaml.
type contract struct {
	root    map[string]any
	paths   map[string]any
	schemas map[string]any
}

func newContract(document []byte) (*contract, error) {
	value, err := parseYAML(document)
	if err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("contract document is not a mapping")
	}
	paths, ok := root["paths"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("contract document has no paths mapping")
	}
	components, ok := root["components"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("contract document has no components mapping")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("contract document has no components.schemas mapping")
	}
	c := &contract{root: root, paths: paths, schemas: schemas}
	if err := c.checkSchemaSubset(); err != nil {
		return nil, err
	}
	return c, nil
}

// operations returns every documented "METHOD path" pair.
func (c *contract) operations() []string {
	var out []string
	for path, item := range c.paths {
		methods, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for method := range methods {
			out = append(out, strings.ToUpper(method)+" "+path)
		}
	}
	sort.Strings(out)
	return out
}

// operation returns the documented operation for one request, matching path
// templates such as /debuglet/{id}/logs.
func (c *contract) operation(method, path string) (map[string]any, string, error) {
	item, template, err := c.pathItem(path)
	if err != nil {
		return nil, "", err
	}
	operation, ok := item[strings.ToLower(method)].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("contract has no %s operation for %s", method, template)
	}
	return operation, template, nil
}

func (c *contract) pathItem(path string) (map[string]any, string, error) {
	if item, ok := c.paths[path].(map[string]any); ok {
		return item, path, nil
	}
	requested := strings.Split(path, "/")
	for template, value := range c.paths {
		candidate := strings.Split(template, "/")
		if len(candidate) != len(requested) {
			continue
		}
		matched := true
		for i := range candidate {
			if strings.HasPrefix(candidate[i], "{") && strings.HasSuffix(candidate[i], "}") {
				if requested[i] == "" {
					matched = false
					break
				}
				continue
			}
			if candidate[i] != requested[i] {
				matched = false
				break
			}
		}
		if matched {
			item, ok := value.(map[string]any)
			if !ok {
				return nil, "", fmt.Errorf("contract path %s is not a mapping", template)
			}
			return item, template, nil
		}
	}
	return nil, "", fmt.Errorf("contract documents no path for %s", path)
}

// jsonSchema returns the request-body schema of an operation, or nil when the
// operation documents no JSON body.
func jsonSchema(operation map[string]any, key string) any {
	body, ok := operation[key].(map[string]any)
	if !ok {
		return nil
	}
	content, ok := body["content"].(map[string]any)
	if !ok {
		return nil
	}
	media, ok := content["application/json"].(map[string]any)
	if !ok {
		return nil
	}
	return media["schema"]
}

// responseSchema reports what the contract documents for one status code:
// whether the status is documented at all, whether it carries a body, and the
// JSON schema of that body when the body is JSON.
func responseSchema(operation map[string]any, status int) (schema any, documented, hasBody bool) {
	responses, ok := operation["responses"].(map[string]any)
	if !ok {
		return nil, false, false
	}
	response, ok := responses[strconv.Itoa(status)].(map[string]any)
	if !ok {
		return nil, false, false
	}
	content, ok := response["content"].(map[string]any)
	if !ok {
		// A documented response without a body, such as 204.
		return nil, true, false
	}
	media, ok := content["application/json"].(map[string]any)
	if !ok {
		// A documented body in another representation, such as the served
		// contract document itself.
		return nil, true, true
	}
	return media["schema"], true, true
}

// parameterNames returns the documented query parameters of an operation and
// the subset of them that is required.
func parameterNames(operation map[string]any) (documented, required map[string]bool) {
	documented, required = map[string]bool{}, map[string]bool{}
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		return documented, required
	}
	for _, entry := range parameters {
		parameter, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if location, _ := parameter["in"].(string); location != "query" {
			continue
		}
		name, _ := parameter["name"].(string)
		documented[name] = true
		if mandatory, _ := parameter["required"].(bool); mandatory {
			required[name] = true
		}
	}
	return documented, required
}

// ------------------------------------------------------------------ validator

// validateJSON decodes data and checks it against schema, returning every
// violation found. Numbers keep their exact text so integer fields cannot pass
// by being converted to a float.
func (c *contract) validateJSON(schema any, data []byte, where string) []string {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return []string{fmt.Sprintf("%s: body is not JSON: %v", where, err)}
	}
	if decoder.More() {
		return []string{fmt.Sprintf("%s: trailing data after the JSON value", where)}
	}
	return c.validate(schema, value, where)
}

func (c *contract) validate(schema any, value any, where string) []string {
	resolved, err := c.resolve(schema)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", where, err)}
	}
	if options, ok := resolved["oneOf"].([]any); ok {
		var matched int
		for _, option := range options {
			if len(c.validate(option, value, where)) == 0 {
				matched++
			}
		}
		if matched != 1 {
			return []string{fmt.Sprintf("%s: matches %d of the %d documented alternatives, want exactly 1", where, matched, len(options))}
		}
		return nil
	}
	if value == nil {
		if nullable, _ := resolved["nullable"].(bool); nullable {
			return nil
		}
		return []string{fmt.Sprintf("%s: is null but the contract does not allow null", where)}
	}
	if enum, ok := resolved["enum"].([]any); ok {
		found := false
		for _, allowed := range enum {
			if fmt.Sprint(allowed) == fmt.Sprint(value) {
				found = true
				break
			}
		}
		if !found {
			return []string{fmt.Sprintf("%s: value %v is not one of the documented values %v", where, value, enum)}
		}
	}
	declared, _ := resolved["type"].(string)
	switch declared {
	case "object":
		return c.validateObject(resolved, value, where)
	case "array":
		return c.validateArray(resolved, value, where)
	case "string":
		return validateString(resolved, value, where)
	case "integer", "number":
		return validateNumber(resolved, value, where, declared == "integer")
	case "boolean":
		if _, ok := value.(bool); !ok {
			return []string{fmt.Sprintf("%s: %T is not a boolean", where, value)}
		}
	case "":
		return []string{fmt.Sprintf("%s: the contract declares no type", where)}
	default:
		return []string{fmt.Sprintf("%s: unsupported documented type %q", where, declared)}
	}
	return nil
}

func (c *contract) validateObject(schema map[string]any, value any, where string) []string {
	object, ok := value.(map[string]any)
	if !ok {
		return []string{fmt.Sprintf("%s: %T is not an object", where, value)}
	}
	properties, _ := schema["properties"].(map[string]any)
	var problems []string
	if required, ok := schema["required"].([]any); ok {
		for _, name := range required {
			key := fmt.Sprint(name)
			if _, present := object[key]; !present {
				problems = append(problems, fmt.Sprintf("%s: required field %q is missing", where, key))
			}
		}
	}
	additional, hasAdditional := schema["additionalProperties"].(bool)
	for key, field := range object {
		property, documented := properties[key]
		if !documented {
			if hasAdditional && !additional {
				problems = append(problems, fmt.Sprintf("%s: field %q is not documented", where, key))
			}
			continue
		}
		problems = append(problems, c.validate(property, field, where+"."+key)...)
	}
	return problems
}

func (c *contract) validateArray(schema map[string]any, value any, where string) []string {
	array, ok := value.([]any)
	if !ok {
		return []string{fmt.Sprintf("%s: %T is not an array", where, value)}
	}
	items, ok := schema["items"]
	if !ok {
		return []string{fmt.Sprintf("%s: the contract documents no items schema", where)}
	}
	var problems []string
	for i, element := range array {
		problems = append(problems, c.validate(items, element, fmt.Sprintf("%s[%d]", where, i))...)
	}
	return problems
}

func validateString(schema map[string]any, value any, where string) []string {
	text, ok := value.(string)
	if !ok {
		return []string{fmt.Sprintf("%s: %T is not a string", where, value)}
	}
	switch format, _ := schema["format"].(string); format {
	case "byte":
		if _, err := base64.StdEncoding.DecodeString(text); err != nil {
			return []string{fmt.Sprintf("%s: is not base64 as documented", where)}
		}
	case "date-time":
		if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
			return []string{fmt.Sprintf("%s: is not an RFC3339 timestamp as documented", where)}
		}
	case "uuid":
		if !looksLikeUUID(text) {
			return []string{fmt.Sprintf("%s: %q is not a canonical UUID as documented", where, text)}
		}
	}
	if pattern, ok := schema["pattern"].(string); ok && !regexp.MustCompile(pattern).MatchString(text) {
		return []string{fmt.Sprintf("%s: %q does not match the documented pattern %s", where, text, pattern)}
	}
	return nil
}

func validateNumber(schema map[string]any, value any, where string, integer bool) []string {
	number, ok := value.(json.Number)
	if !ok {
		return []string{fmt.Sprintf("%s: %T is not a number", where, value)}
	}
	if integer {
		if _, err := number.Int64(); err != nil {
			return []string{fmt.Sprintf("%s: %s is not an integer as documented", where, number)}
		}
	}
	exact, err := number.Float64()
	if err != nil {
		return []string{fmt.Sprintf("%s: %s is not a number", where, number)}
	}
	var problems []string
	if minimum, ok := numericBound(schema["minimum"]); ok && exact < minimum {
		problems = append(problems, fmt.Sprintf("%s: %s is below the documented minimum %v", where, number, minimum))
	}
	if maximum, ok := numericBound(schema["maximum"]); ok && exact > maximum {
		problems = append(problems, fmt.Sprintf("%s: %s is above the documented maximum %v", where, number, maximum))
	}
	return problems
}

func numericBound(value any) (float64, bool) {
	switch bound := value.(type) {
	case int64:
		return float64(bound), true
	case float64:
		return bound, true
	default:
		return 0, false
	}
}

func looksLikeUUID(text string) bool {
	if len(text) != 36 {
		return false
	}
	for i := 0; i < len(text); i++ {
		switch i {
		case 8, 13, 18, 23:
			if text[i] != '-' {
				return false
			}
		default:
			c := text[i]
			if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// resolve follows a $ref into components.schemas.
func (c *contract) resolve(schema any) (map[string]any, error) {
	for depth := 0; depth < 8; depth++ {
		mapping, ok := schema.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("schema is %T, not a mapping", schema)
		}
		reference, ok := mapping["$ref"].(string)
		if !ok {
			return mapping, nil
		}
		const prefix = "#/components/schemas/"
		if !strings.HasPrefix(reference, prefix) {
			return nil, fmt.Errorf("unsupported reference %q", reference)
		}
		target, ok := c.schemas[strings.TrimPrefix(reference, prefix)]
		if !ok {
			return nil, fmt.Errorf("reference %q has no target", reference)
		}
		schema = target
	}
	return nil, fmt.Errorf("reference chain is too deep")
}

// ------------------------------------------------------- supported schema subset

// The checks above read one small schema dialect. The document may use only
// that dialect, because a keyword outside it is read by nothing: it would
// describe a constraint no exchange is ever held to, which is worse than
// documenting no constraint at all. checkSchemaSubset rejects unsupported
// schema constructs in every position it visits (named schemas, parameter,
// request body, response body and response header schemas, and everything
// nested in them), and it reads the definitions themselves rather than the
// values that happen to be exchanged, so an omitted optional property, an
// empty array, a null, an alternative that does not match or a reference
// cannot hide an unsupported construct from it. Which values are actually
// checked against these schemas is decided by the exchange suite, not here.
//
// The three tables below are the dialect. Extending the validator means adding
// the keyword here and implementing it above, in that order.

// schemaAnnotations document the contract for a reader and assert nothing about
// a value, so every check ignores them by design.
var schemaAnnotations = []string{"deprecated", "description", "example", "title"}

// schemaCommonAssertions are read whatever type a schema declares: type selects
// the check, nullable admits a JSON null and enum pins the accepted values.
var schemaCommonAssertions = []string{"enum", "nullable", "type"}

// schemaTypeAssertions maps each implemented type to the assertions the check
// for that type reads, and nothing else reads them: only validateObject reads
// properties, required and additionalProperties, only validateArray reads
// items, and only validateNumber reads minimum and maximum. A type that is
// absent is not implemented at all.
var schemaTypeAssertions = map[string][]string{
	"object":  {"additionalProperties", "properties", "required"},
	"array":   {"items"},
	"string":  {"format", "pattern"},
	"integer": {"format", "maximum", "minimum"},
	"number":  {"maximum", "minimum"},
	"boolean": nil,
}

// schemaFormats lists the formats each type's check implements: validateString
// decodes base64 and canonical UUID text, and validateNumber parses an integer
// as an int64, which is what format int64 documents. Every other format, and
// any format on a type whose check does not read one, would be decoration.
var schemaFormats = map[string][]string{
	"string":  {"byte", "uuid", "date-time"},
	"integer": {"int64"},
}

// checkSchemaSubset walks every schema the document declares and reports each
// one that uses a construct the checks above do not implement, naming the
// keyword and where in the document it sits.
func (c *contract) checkSchemaSubset() error {
	var problems []string
	for _, name := range sortedKeys(c.schemas) {
		c.checkSchema(c.schemas[name], "components.schemas."+name, &problems)
	}
	for _, path := range sortedKeys(c.paths) {
		item, ok := c.paths[path].(map[string]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("paths.%s: is not a mapping", path))
			continue
		}
		for _, method := range sortedKeys(item) {
			where := fmt.Sprintf("paths.%s.%s", path, method)
			operation, ok := item[method].(map[string]any)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: is not an operation mapping", where))
				continue
			}
			c.checkOperationSchemas(operation, where, &problems)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("the document uses schema constructs this file does not check:\n  %s", strings.Join(problems, "\n  "))
}

// checkOperationSchemas walks the schemas one operation declares: those of its
// parameters, of its request body and of every response body and response
// header. A declared position without a schema is reported too, so the walk
// cannot pass over a shape by finding nothing to look at.
func (c *contract) checkOperationSchemas(operation map[string]any, where string, problems *[]string) {
	if parameters, present := operation["parameters"]; present {
		list, ok := parameters.([]any)
		if !ok {
			*problems = append(*problems, fmt.Sprintf("%s.parameters: is not a sequence", where))
		}
		for i, entry := range list {
			parameter, ok := entry.(map[string]any)
			if !ok {
				*problems = append(*problems, fmt.Sprintf("%s.parameters[%d]: is not a mapping", where, i))
				continue
			}
			label, _ := parameter["name"].(string)
			if label == "" {
				label = strconv.Itoa(i)
			}
			at := fmt.Sprintf("%s.parameters.%s", where, label)
			schema, present := parameter["schema"]
			if !present {
				*problems = append(*problems, fmt.Sprintf("%s: documents no schema", at))
				continue
			}
			c.checkSchema(schema, at+".schema", problems)
		}
	}
	if body, present := operation["requestBody"]; present {
		c.checkContentSchemas(body, where+".requestBody", problems)
	}
	responses, ok := operation["responses"].(map[string]any)
	if !ok {
		*problems = append(*problems, fmt.Sprintf("%s.responses: is not a mapping", where))
		return
	}
	for _, status := range sortedKeys(responses) {
		at := fmt.Sprintf("%s.responses.%s", where, status)
		response, ok := responses[status].(map[string]any)
		if !ok {
			*problems = append(*problems, fmt.Sprintf("%s: is not a mapping", at))
			continue
		}
		// A reusable response would need resolving, which responseSchema does
		// not do: it would read the reference as a response without a body and
		// never look at the schema behind it.
		if _, present := response["$ref"]; present {
			*problems = append(*problems, fmt.Sprintf("%s: a response $ref is not resolved, so the body behind it is never checked", at))
			continue
		}
		// A documented response without a body, such as 204, declares no schema.
		if _, present := response["content"]; present {
			c.checkContentSchemas(response, at, problems)
		}
		headers, _ := response["headers"].(map[string]any)
		for _, name := range sortedKeys(headers) {
			header, ok := headers[name].(map[string]any)
			if !ok {
				*problems = append(*problems, fmt.Sprintf("%s.headers.%s: is not a mapping", at, name))
				continue
			}
			schema, present := header["schema"]
			if !present {
				*problems = append(*problems, fmt.Sprintf("%s.headers.%s: documents no schema", at, name))
				continue
			}
			c.checkSchema(schema, fmt.Sprintf("%s.headers.%s.schema", at, name), problems)
		}
	}
}

// checkContentSchemas walks the schema of every media type of one body.
func (c *contract) checkContentSchemas(body any, where string, problems *[]string) {
	mapping, ok := body.(map[string]any)
	if !ok {
		*problems = append(*problems, fmt.Sprintf("%s: is not a mapping", where))
		return
	}
	content, ok := mapping["content"].(map[string]any)
	if !ok {
		*problems = append(*problems, fmt.Sprintf("%s.content: is not a mapping", where))
		return
	}
	for _, media := range sortedKeys(content) {
		at := fmt.Sprintf("%s.content.%s", where, media)
		entry, ok := content[media].(map[string]any)
		if !ok {
			*problems = append(*problems, fmt.Sprintf("%s: is not a mapping", at))
			continue
		}
		schema, present := entry["schema"]
		if !present {
			*problems = append(*problems, fmt.Sprintf("%s: documents no schema", at))
			continue
		}
		c.checkSchema(schema, at+".schema", problems)
	}
}

// checkSchema reports the unsupported constructs of one schema object and of
// every schema nested in it.
func (c *contract) checkSchema(schema any, where string, problems *[]string) {
	mapping, ok := schema.(map[string]any)
	if !ok {
		*problems = append(*problems, fmt.Sprintf("%s: is %T, not a schema mapping", where, schema))
		return
	}
	if reference, present := mapping["$ref"]; present {
		if _, ok := reference.(string); !ok {
			*problems = append(*problems, fmt.Sprintf("%s: $ref is %T, not a string", where, reference))
			return
		}
		// resolve reads the reference and nothing beside it. The target is a
		// named schema, so it is walked once under its own location above.
		checkExclusiveKeyword(mapping, "$ref", where, problems)
		if _, err := c.resolve(mapping); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: %v", where, err))
		}
		return
	}
	if alternatives, present := mapping["oneOf"]; present {
		// validate answers from the alternatives alone and returns, so a
		// keyword beside oneOf is never read.
		checkExclusiveKeyword(mapping, "oneOf", where, problems)
		options, ok := alternatives.([]any)
		if !ok || len(options) == 0 {
			*problems = append(*problems, fmt.Sprintf("%s: oneOf is not a sequence of alternatives", where))
			return
		}
		for i, option := range options {
			c.checkSchema(option, fmt.Sprintf("%s.oneOf[%d]", where, i), problems)
		}
		return
	}
	declared, present := mapping["type"]
	if !present {
		*problems = append(*problems, fmt.Sprintf("%s: declares no type, $ref or oneOf, so no check applies to its values", where))
		return
	}
	name, ok := declared.(string)
	if !ok {
		*problems = append(*problems, fmt.Sprintf("%s: type is %T, not a string", where, declared))
		return
	}
	assertions, implemented := schemaTypeAssertions[name]
	if !implemented {
		*problems = append(*problems, fmt.Sprintf("%s: type %q is not implemented", where, name))
		return
	}
	for _, key := range sortedKeys(mapping) {
		switch {
		case slices.Contains(schemaAnnotations, key), slices.Contains(schemaCommonAssertions, key):
		case slices.Contains(assertions, key):
		default:
			if readers := schemaAssertionReaders(key); len(readers) > 0 {
				*problems = append(*problems, fmt.Sprintf("%s: %q is read for type %s, not for type %q",
					where, key, strings.Join(readers, " and "), name))
				continue
			}
			*problems = append(*problems, fmt.Sprintf("%s: keyword %q is not implemented", where, key))
		}
	}
	if enum, present := mapping["enum"]; present {
		if values, ok := enum.([]any); !ok || len(values) == 0 {
			*problems = append(*problems, fmt.Sprintf("%s: enum is not a sequence of documented values", where))
		}
	}
	if nullable, present := mapping["nullable"]; present {
		if _, ok := nullable.(bool); !ok {
			*problems = append(*problems, fmt.Sprintf("%s: nullable is %T, and only a boolean is read", where, nullable))
		}
	}
	switch name {
	case "object":
		c.checkObjectSchema(mapping, where, problems)
	case "array":
		c.checkArraySchema(mapping, where, problems)
	case "string", "integer", "number":
		checkScalarSchema(mapping, name, where, problems)
	}
}

// checkObjectSchema checks what validateObject reads and walks the documented
// properties.
func (c *contract) checkObjectSchema(mapping map[string]any, where string, problems *[]string) {
	properties, declared := mapping["properties"]
	fields, _ := properties.(map[string]any)
	if declared && fields == nil {
		*problems = append(*problems, fmt.Sprintf("%s: properties is %T, not a mapping", where, properties))
	}
	// An omitted additionalProperties means true, which is what validateObject
	// does with it: undocumented fields pass and documented ones are checked.
	// A schema in its place is not read at all, so unknown fields would pass
	// against a constraint that looks enforced.
	if additional, present := mapping["additionalProperties"]; present {
		if _, ok := additional.(bool); !ok {
			*problems = append(*problems, fmt.Sprintf("%s: additionalProperties is %T, and only a boolean is read", where, additional))
		}
	}
	// validateObject enforces the presence of every required name, with or
	// without a property schema for it, but reads required only as a sequence.
	if required, present := mapping["required"]; present {
		if _, ok := required.([]any); !ok {
			*problems = append(*problems, fmt.Sprintf("%s: required is not a sequence of field names", where))
		}
	}
	for _, key := range sortedKeys(fields) {
		c.checkSchema(fields[key], where+".properties."+key, problems)
	}
}

// checkArraySchema checks what validateArray reads and walks the element schema.
func (c *contract) checkArraySchema(mapping map[string]any, where string, problems *[]string) {
	items, present := mapping["items"]
	if !present {
		*problems = append(*problems, fmt.Sprintf("%s: documents no items schema", where))
		return
	}
	c.checkSchema(items, where+".items", problems)
}

// checkScalarSchema checks the format and the numeric bounds of a string,
// integer or number schema against what validateString and validateNumber
// implement.
func checkScalarSchema(mapping map[string]any, name, where string, problems *[]string) {
	if format, present := mapping["format"]; present {
		text, ok := format.(string)
		if !ok || !slices.Contains(schemaFormats[name], text) {
			*problems = append(*problems, fmt.Sprintf("%s: format %v is not implemented for type %q", where, format, name))
		}
	}
	if pattern, present := mapping["pattern"]; present {
		text, ok := pattern.(string)
		if !ok {
			*problems = append(*problems, fmt.Sprintf("%s: pattern is %T, and only a string is read", where, pattern))
		} else if _, err := regexp.Compile(text); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: pattern %q does not compile: %v", where, text, err))
		}
	}
	for _, bound := range []string{"maximum", "minimum"} {
		value, present := mapping[bound]
		if !present {
			continue
		}
		if _, ok := numericBound(value); !ok {
			*problems = append(*problems, fmt.Sprintf("%s: %s is %T, and only a number is read", where, bound, value))
		}
	}
}

// checkExclusiveKeyword reports the keywords beside one that is read on its
// own, because nothing reads them.
func checkExclusiveKeyword(mapping map[string]any, keyword, where string, problems *[]string) {
	for _, key := range sortedKeys(mapping) {
		if key == keyword || slices.Contains(schemaAnnotations, key) {
			continue
		}
		*problems = append(*problems, fmt.Sprintf("%s: %q is not read beside %q", where, key, keyword))
	}
}

// schemaAssertionReaders names the types whose check reads one assertion, so a
// misplaced keyword can say where it would have been read.
func schemaAssertionReaders(keyword string) []string {
	var readers []string
	for name, assertions := range schemaTypeAssertions {
		if slices.Contains(assertions, keyword) {
			readers = append(readers, strconv.Quote(name))
		}
	}
	sort.Strings(readers)
	return readers
}

// sortedKeys returns the keys of a parsed mapping in a stable order, so the
// reported problems do not depend on map iteration.
func sortedKeys(mapping map[string]any) []string {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
