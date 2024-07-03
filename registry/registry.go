package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
)

type FileSystemRegistry struct {
	// root string
	fs fs.FS
}

func NewFileSystemRegistry(root string) (*FileSystemRegistry, error) {
	cleanRoot := filepath.Clean(root)
	if stat, err := os.Stat(cleanRoot); err != nil {
		return nil, fmt.Errorf("failed to stat %q: %w", cleanRoot, err)
	} else if !stat.IsDir() {
		return nil, fmt.Errorf("specified path %q is not a directory", cleanRoot)
	}

	return &FileSystemRegistry{
		fs: os.DirFS(cleanRoot),
	}, nil
}

// var manifestRegex = regexp.MustCompile(`^([a-z][a-z0-9.]+(?:[0-9]+))/`)
// var manifestRegex = regexp.MustCompile(`^([a-z0-9])`)

type ManifestPath struct {
	Host   string
	Port   string
	Path   string
	Tag    string
	SHA256 string
}

// var (
// 	pathRegex = regexp.MustCompile(`^([a-z0-9/]+[a-z0-9])$`)
// )

type Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"layers"`
}

var (
	rawSHA256Regex      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	prefixedSHA256Regex = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)
	tagRegex            = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)
)

func (r *FileSystemRegistry) Manifest(where ManifestPath) (*Manifest, error) {
	// host and port are ignored

	cleanPath := path.Clean(where.Path)
	if where.SHA256 != "" {
		if !rawSHA256Regex.MatchString(where.SHA256) {
			// ollama got popped due to path traversal in the sha256
			return nil, fmt.Errorf("bad SHA256: %q", where.SHA256)
		}

		// TODO: manifest via sha256, i.e. docker.lol/image/path@sha256:deadbeef
		return nil, errors.New("not implemented")
	}

	if !tagRegex.MatchString(where.Tag) {
		return nil, fmt.Errorf("bad tag: %q", where.Tag)
	}

	linkPath := path.Join("docker", "registry", "v2", "repositories", cleanPath, "_manifests", "tags", where.Tag, "current", "link")
	f, err := r.fs.Open(linkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open manifest link for %s:%s: %w", cleanPath, where.Tag, err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest link for %s:%s: %w", cleanPath, where.Tag, err)
	}

	if !prefixedSHA256Regex.Match(b) {
		return nil, fmt.Errorf("bad manifest link contents for %s:%s: %w", cleanPath, where.Tag, err)
	}

	// TODO: limit this read to <1MB
	reader, err := r.blob(string(b))
	if err != nil {
		return nil, fmt.Errorf("failed to read blob of manifest %s:%s: %w", cleanPath, where.Tag, err)
	}
	defer reader.Close()
	b, err = io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error while reading blob of manifest %s:%s: %w", cleanPath, where.Tag, err)
	}

	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest link for %s:%s: %w", cleanPath, where.Tag, err)
	}

	if m.SchemaVersion != 2 {
		return nil, fmt.Errorf("unrecognized schema version for %s:%s: %d", cleanPath, where.Tag, m.SchemaVersion)
	}
	// TODO: implement manifest list - extra return arg?
	if m.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		return nil, fmt.Errorf("unrecognized media type for %s:%s: %q", cleanPath, where.Tag, m.MediaType)
	}

	return &m, nil
}

func (r *FileSystemRegistry) Blob(sha256 string) (io.ReadCloser, error) {
	if !rawSHA256Regex.MatchString(sha256) {
		return nil, fmt.Errorf("invalid SHA256: %q", sha256)
	}
	return r.blob(sha256)
}

func (r *FileSystemRegistry) blob(sha256 string) (io.ReadCloser, error) {
	where := path.Join("docker", "registry", "v2", "blobs", "sha256", sha256[0:2], sha256, "data")
	f, err := r.fs.Open(where)
	if err != nil {
		return nil, fmt.Errorf("failed to open blob %q: %w", sha256, err)
	}
	return f, nil
}
