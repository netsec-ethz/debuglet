package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

// TestParseVersionRejectsMalformedInput keeps a mistyped compiler version from
// reaching the plugins, where it would silently become part of the generated
// headers.
func TestParseVersionRejectsMalformedInput(t *testing.T) {
	for _, text := range []string{"", "7", "7.34", "7.34.0.1", "7.34.x", "-1.34.0", "7.-1.0", "v7.34.0", "7 34 0"} {
		if version, err := parseVersion(text); err == nil {
			t.Errorf("parseVersion(%q) accepted the value as %v", text, version)
		}
	}
}

func TestParseVersionReadsEachComponent(t *testing.T) {
	version, err := parseVersion("7.34.0")
	if err != nil {
		t.Fatalf("parseVersion: %v", err)
	}
	if version.GetMajor() != 7 || version.GetMinor() != 34 || version.GetPatch() != 0 {
		t.Errorf("parsed %d.%d.%d, want 7.34.0",
			version.GetMajor(), version.GetMinor(), version.GetPatch())
	}
}

// writeDescriptorSet stores a descriptor set the way the protocol compiler
// front end hands one over.
func writeDescriptorSet(t *testing.T, names ...string) string {
	t.Helper()
	set := &descriptorpb.FileDescriptorSet{}
	for _, name := range names {
		set.File = append(set.File, &descriptorpb.FileDescriptorProto{
			Name:   proto.String(name),
			Syntax: proto.String("proto3"),
			// Every entry arrives with source information; only the files
			// being generated are supposed to keep it.
			SourceCodeInfo: &descriptorpb.SourceCodeInfo{},
		})
	}
	body, err := proto.Marshal(set)
	if err != nil {
		t.Fatalf("marshal descriptor set: %v", err)
	}
	path := filepath.Join(t.TempDir(), "descriptorset")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write descriptor set: %v", err)
	}
	return path
}

// TestBuildRequestRejectsMissingTarget fails loudly when the descriptor set
// does not hold the file that was asked for, instead of generating nothing.
func TestBuildRequestRejectsMissingTarget(t *testing.T) {
	path := writeDescriptorSet(t, "dependency.proto", "present.proto")
	request, err := buildRequest(path, []string{"present.proto", "absent.proto"}, "", nil)
	if err == nil {
		t.Fatalf("buildRequest accepted a missing target and returned %v", request)
	}
	if !strings.Contains(err.Error(), "absent.proto") {
		t.Errorf("error %q does not name the missing target", err)
	}
}

func TestBuildRequestRejectsUnreadableDescriptorSet(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := buildRequest(missing, []string{"a.proto"}, "", nil); err == nil {
		t.Error("buildRequest accepted a descriptor set that does not exist")
	}
	damaged := filepath.Join(t.TempDir(), "damaged")
	if err := os.WriteFile(damaged, []byte("not a descriptor set"), 0o600); err != nil {
		t.Fatalf("write damaged descriptor set: %v", err)
	}
	if _, err := buildRequest(damaged, []string{"a.proto"}, "", nil); err == nil {
		t.Error("buildRequest accepted bytes that are not a descriptor set")
	}
}

// TestBuildRequestKeepsSourceInfoOnTargetsOnly reproduces what the protocol
// compiler sends: comments travel with the files being generated, and
// dependencies arrive without them.
func TestBuildRequestKeepsSourceInfoOnTargetsOnly(t *testing.T) {
	path := writeDescriptorSet(t, "dependency.proto", "target.proto")
	version, err := parseVersion("7.34.0")
	if err != nil {
		t.Fatalf("parseVersion: %v", err)
	}
	request, err := buildRequest(path, []string{"target.proto"}, "paths=source_relative", version)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if got := request.GetFileToGenerate(); len(got) != 1 || got[0] != "target.proto" {
		t.Errorf("files to generate %v, want [target.proto]", got)
	}
	if got := request.GetParameter(); got != "paths=source_relative" {
		t.Errorf("parameter %q, want paths=source_relative", got)
	}
	if request.GetCompilerVersion().GetMinor() != 34 {
		t.Errorf("compiler version %v was not passed through", request.GetCompilerVersion())
	}
	if got := request.GetSourceFileDescriptors(); len(got) != 1 || got[0].GetName() != "target.proto" {
		t.Fatalf("source file descriptors %v, want only target.proto", got)
	}
	for _, file := range request.GetProtoFile() {
		hasInfo := file.GetSourceCodeInfo() != nil
		if want := file.GetName() == "target.proto"; hasInfo != want {
			t.Errorf("%s carries source information %v, want %v", file.GetName(), hasInfo, want)
		}
	}
}

// TestWriteFilesRejectsInsertionPoint refuses a response this command cannot
// apply rather than dropping the content it carries.
func TestWriteFilesRejectsInsertionPoint(t *testing.T) {
	response := &pluginpb.CodeGeneratorResponse{File: []*pluginpb.CodeGeneratorResponse_File{{
		Name:           proto.String("protocol/protocol.pb.go"),
		InsertionPoint: proto.String("imports"),
		Content:        proto.String("package protocol\n"),
	}}}
	out := t.TempDir()
	if _, err := writeFiles(out, "protoc-gen-go", response); err == nil {
		t.Fatal("writeFiles accepted an insertion point")
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("read output directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("output directory holds %d entries after a rejected response", len(entries))
	}
}

// TestWriteFilesRejectsPathsOutsideOutput keeps a plugin from writing anywhere
// but below the directory it was given.
func TestWriteFilesRejectsPathsOutsideOutput(t *testing.T) {
	for _, name := range []string{"", "../escaped.go", "/tmp/absolute.go", "protocol/../../escaped.go"} {
		response := &pluginpb.CodeGeneratorResponse{File: []*pluginpb.CodeGeneratorResponse_File{{
			Name:    proto.String(name),
			Content: proto.String("package protocol\n"),
		}}}
		if _, err := writeFiles(t.TempDir(), "protoc-gen-go", response); err == nil {
			t.Errorf("writeFiles accepted the output path %q", name)
		}
	}
}

func TestWriteFilesCreatesTheRequestedTree(t *testing.T) {
	response := &pluginpb.CodeGeneratorResponse{File: []*pluginpb.CodeGeneratorResponse_File{{
		Name:    proto.String("protocol/protocol.pb.go"),
		Content: proto.String("package protocol\n"),
	}}}
	out := t.TempDir()
	written, err := writeFiles(out, "protoc-gen-go", response)
	if err != nil {
		t.Fatalf("writeFiles: %v", err)
	}
	if written != 1 {
		t.Errorf("wrote %d files, want 1", written)
	}
	body, err := os.ReadFile(filepath.Join(out, "protocol", "protocol.pb.go"))
	if err != nil {
		t.Fatalf("read generated file: %v", err)
	}
	if string(body) != "package protocol\n" {
		t.Errorf("generated file holds %q", body)
	}
}

// TestRunRequiresEveryInput keeps a partly configured invocation from
// producing an incomplete generation that would then be compared.
func TestRunRequiresEveryInput(t *testing.T) {
	path := writeDescriptorSet(t, "target.proto")
	complete := []string{
		"-descriptor-set", path,
		"-out", t.TempDir(),
		"-compiler-version", "7.34.0",
		"-target", "target.proto",
		"/nonexistent-plugin",
	}
	for _, dropped := range []string{"-descriptor-set", "-out", "-compiler-version", "-target"} {
		args := without(complete, dropped)
		if err := run(args); err == nil {
			t.Errorf("run without %s succeeded", dropped)
		} else if !strings.Contains(err.Error(), dropped) {
			t.Errorf("run without %s reported %q", dropped, err)
		}
	}
	if err := run(complete[:len(complete)-1]); err == nil {
		t.Error("run without a plugin succeeded")
	}
}

// without drops a flag and the value that follows it.
func without(args []string, flag string) []string {
	trimmed := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		trimmed = append(trimmed, args[i])
	}
	return trimmed
}
