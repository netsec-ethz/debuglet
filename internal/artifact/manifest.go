// Package artifact defines the private distribution manifest shared by packaging and runtime verification.
package artifact

// File records an exact payload's bytes and SHA-256 digest.
type File struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Manifest identifies one complete installation. It never hashes itself.
type Manifest struct {
	SchemaVersion    int             `json:"schema_version"`
	Version          string          `json:"version"`
	SourceSHA        string          `json:"source_sha"`
	Dirty            bool            `json:"dirty"`
	GoVersion        string          `json:"go_version"`
	GOOS             string          `json:"goos"`
	GOARCH           string          `json:"goarch"`
	GuestABI         string          `json:"guest_abi"`
	Files            map[string]File `json:"files"`
	BuildPipelineURL string          `json:"build_pipeline_url"`
}
