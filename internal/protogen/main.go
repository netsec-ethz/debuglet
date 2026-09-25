// Command protogen renders generated Go sources from a compiled protocol
// descriptor set using the pinned protoc-gen-go plugins. It is a repository
// tool, never shipped or required by the installed runtime.
//
// It takes the place of a local protoc installation. The descriptor set holds
// the compiled protocol definition; this command hands that definition to each
// plugin in the same code generator request protoc would have sent, including
// the protocol compiler version recorded in the generated file headers. The
// result is byte-for-byte what the pinned protoc and plugins produce, so the
// committed sources can be compared against a fresh generation without
// installing a protocol compiler.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "protogen:", err)
		os.Exit(1)
	}
}

type repeated []string

func (r *repeated) String() string { return strings.Join(*r, ",") }

func (r *repeated) Set(value string) error {
	if value == "" {
		return errors.New("empty value")
	}
	*r = append(*r, value)
	return nil
}

func run(args []string) error {
	var targets repeated
	flags := flag.NewFlagSet("protogen", flag.ContinueOnError)
	descriptorSet := flags.String("descriptor-set", "", "compiled FileDescriptorSet holding the protocol definition")
	out := flags.String("out", "", "directory the generated sources are written below")
	parameter := flags.String("parameter", "", "generator parameter passed to every plugin")
	compilerVersion := flags.String("compiler-version", "", "protocol compiler version recorded in the generated headers")
	flags.Var(&targets, "target", "descriptor set entry to generate, repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	plugins := flags.Args()
	switch {
	case *descriptorSet == "":
		return errors.New("-descriptor-set is required")
	case *out == "":
		return errors.New("-out is required")
	case *compilerVersion == "":
		return errors.New("-compiler-version is required")
	case len(targets) == 0:
		return errors.New("at least one -target is required")
	case len(plugins) == 0:
		return errors.New("at least one plugin executable is required")
	}
	version, err := parseVersion(*compilerVersion)
	if err != nil {
		return err
	}
	request, err := buildRequest(*descriptorSet, targets, *parameter, version)
	if err != nil {
		return err
	}
	body, err := proto.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal generator request: %w", err)
	}
	for _, plugin := range plugins {
		response, err := invoke(plugin, body)
		if err != nil {
			return err
		}
		written, err := writeFiles(*out, plugin, response)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "protogen: %s wrote %d file(s)\n", filepath.Base(plugin), written)
	}
	return nil
}

// parseVersion reads the major.minor.patch form protoc reports for itself.
func parseVersion(text string) (*pluginpb.Version, error) {
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compiler version %q is not major.minor.patch", text)
	}
	numbers := make([]int32, len(parts))
	for i, part := range parts {
		value, err := strconv.ParseInt(part, 10, 32)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("compiler version %q is not major.minor.patch", text)
		}
		numbers[i] = int32(value)
	}
	return &pluginpb.Version{
		Major: proto.Int32(numbers[0]),
		Minor: proto.Int32(numbers[1]),
		Patch: proto.Int32(numbers[2]),
	}, nil
}

func buildRequest(path string, targets []string, parameter string, version *pluginpb.Version) (*pluginpb.CodeGeneratorRequest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read descriptor set: %w", err)
	}
	set := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(raw, set); err != nil {
		return nil, fmt.Errorf("decode descriptor set %s: %w", path, err)
	}
	wanted := make(map[string]bool, len(targets))
	for _, target := range targets {
		wanted[target] = true
	}
	var sources []*descriptorpb.FileDescriptorProto
	found := make(map[string]bool, len(targets))
	for _, file := range set.GetFile() {
		name := file.GetName()
		if !wanted[name] {
			// protoc keeps source information only for the files it generates;
			// dependencies reach the plugins without it.
			file.SourceCodeInfo = nil
			continue
		}
		found[name] = true
		sources = append(sources, file)
	}
	var missing []string
	for _, target := range targets {
		if !found[target] {
			missing = append(missing, target)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("descriptor set %s does not contain %s", path, strings.Join(missing, ", "))
	}
	return &pluginpb.CodeGeneratorRequest{
		FileToGenerate:        targets,
		Parameter:             proto.String(parameter),
		ProtoFile:             set.GetFile(),
		SourceFileDescriptors: sources,
		CompilerVersion:       version,
	}, nil
}

func invoke(plugin string, request []byte) (*pluginpb.CodeGeneratorResponse, error) {
	var stdout bytes.Buffer
	command := exec.Command(plugin)
	command.Stdin = bytes.NewReader(request)
	command.Stdout = &stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("run %s: %w", plugin, err)
	}
	response := &pluginpb.CodeGeneratorResponse{}
	if err := proto.Unmarshal(stdout.Bytes(), response); err != nil {
		return nil, fmt.Errorf("decode response from %s: %w", plugin, err)
	}
	if message := response.GetError(); message != "" {
		return nil, fmt.Errorf("%s: %s", plugin, message)
	}
	if len(response.GetFile()) == 0 {
		return nil, fmt.Errorf("%s produced no files", plugin)
	}
	return response, nil
}

func writeFiles(out, plugin string, response *pluginpb.CodeGeneratorResponse) (int, error) {
	for _, file := range response.GetFile() {
		name := file.GetName()
		if point := file.GetInsertionPoint(); point != "" {
			return 0, fmt.Errorf("%s requested insertion point %q in %s, which is not supported", plugin, point, name)
		}
		local := filepath.FromSlash(name)
		if name == "" || !filepath.IsLocal(local) {
			return 0, fmt.Errorf("%s requested an unsupported output path %q", plugin, name)
		}
		destination := filepath.Join(out, local)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return 0, fmt.Errorf("create output directory: %w", err)
		}
		if err := os.WriteFile(destination, []byte(file.GetContent()), 0o644); err != nil {
			return 0, fmt.Errorf("write %s: %w", destination, err)
		}
	}
	return len(response.GetFile()), nil
}
