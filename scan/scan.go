package scan

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
)

type Result struct {
	Digest     string      `json:"digest"`
	Size       int         `json:"size"`
	Linux      string      `json:"linux,omitempty"`
	Alpine     *Alpine     `json:"alpine,omitempty"`
	Debian     *Debian     `json:"debian,omitempty"`
	SourceCode *SourceCode `json:"sourceCode,omitempty"`
	FileCount  int         `json:"fileCount"`
	DirCount   int         `json:"dirCount"`
	Files      []string    `json:"files"`
}

type Alpine struct {
	Release  string
	Packages []AlpinePackage
}

// func (a Alpine) String() string {
// 	return fmt.Sprintf("Alpine %s (%d packages)", a.Release, len(a.Packages))
// }

// AlpinePackage is an installed package in an Alpine image
// See https://wiki.alpinelinux.org/wiki/Apk_spec#APKINDEX_Format
type AlpinePackage struct {
	Name    string
	Version string
}

func (a AlpinePackage) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s=%s"`, a.Name, a.Version)), nil
}

type Debian struct {
	Release  string          `json:"release,omitempty"`
	Packages []DebianPackage `json:"packages,omitempty"`
}

type DebianPackage struct {
	Name    string
	Version string
}

func (d DebianPackage) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s=%s"`, d.Name, d.Version)), nil
}

// func (a AlpinePackage) String() string {
// 	return fmt.Sprintf("%s-%s", a.Name, a.Version)
// }

type SourceCode struct {
	Go    int      `json:"go,omitempty"`
	GoMod []string `json:"goMod,omitempty"`
}

func (s SourceCode) String() string {
	var parts []string
	if s.Go > 0 {
		parts = append(parts, fmt.Sprintf("Go: %d", s.Go))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// func ScanLayers(registry Registry, manifest *Manifest) error {
// 	for _, layer := range m.Layers {
// 		// if layer.MediaType != "application/vnd.docker.image.rootfs.diff.tar.gzip" {
// 		// 	return fmt.Errorf("unknown layer media type: %q", layer.MediaType)
// 		// }
// 		readLayer(&r, layer)
// 	}
// }

func ScanLayer(reader io.Reader, mediaType string, digest string) (*Result, error) {
	// TODO: check here if we support the media type (gzip, etc)

	// rc, err := fsr.Blob(strings.TrimPrefix(layer.Digest, "sha256:"))
	// require.NoError(t, err)
	// defer rc.Close()

	var uncompressReader io.Reader

	switch mediaType {
	case "application/vnd.docker.image.rootfs.diff.tar.gzip":
		gr, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read gzip'ed layer: %w", err)
		}
		defer gr.Close()
		uncompressReader = gr
	default:
		return nil, fmt.Errorf("unsupported layer media type: %q", mediaType)
	}

	tr := tar.NewReader(uncompressReader)
	var result Result
	result.Digest = digest
	count := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar entry [%d]: %w", count, err)
		}
		count++
		if err := scanFile(&result, header, tr); err != nil {
			return nil, fmt.Errorf("failed to scan file [%d]: %w", count, err)
		}
	}

	return &result, nil
}

func scanFile(result *Result, header *tar.Header, reader io.Reader) error {
	result.Size += int(header.Size)
	if header.FileInfo().IsDir() {
		result.DirCount++
	} else {
		result.FileCount++
	}

	switch header.Name {
	case "etc/alpine-release":
		if result.Alpine == nil {
			result.Alpine = &Alpine{}
		}
		b, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", header.Name, err)
		}
		result.Alpine.Release = strings.TrimSpace(string(b))
	case "lib/apk/db/installed":
		if result.Alpine == nil {
			result.Alpine = &Alpine{}
		}
		if err := scanAPKIndex(result.Alpine, reader); err != nil {
			return fmt.Errorf("failed to scan APK index %q: %w", header.Name, err)
		}
	case "etc/os-release":
		fallthrough
	case "usr/lib/os-release":
		if header.FileInfo().Mode()&os.ModeSymlink != 0 {
			break
		}
		b, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", header.Name, err)
		}

		lines := strings.Split(string(b), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				result.Linux = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				break
			}
		}
	case "var/lib/dpkg/status":
		if result.Debian == nil {
			result.Debian = &Debian{}
		}
		if err := scanDPKGStatus(result.Debian, reader); err != nil {
			return fmt.Errorf("failed to scan DPKG status %q: %w", header.Name, err)
		}
	}

	// images generally shouldn't contain source code
	// notable exception is the Go toolchain itself
	if strings.HasSuffix(header.Name, ".go") {
		if result.SourceCode == nil {
			result.SourceCode = &SourceCode{}
		}
		result.SourceCode.Go++
	} else if strings.HasSuffix(header.Name, "/go.mod") {
		if err := readGoMod(result, reader); err != nil {
			return fmt.Errorf("failed to read %q: %w", header.Name, err)
		}
	}

	return nil
}

func scanAPKIndex(alpine *Alpine, reader io.Reader) error {
	b, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read APK index: %w", err)
	}
	lines := strings.Split(string(b), "\n")

	name := ""
	version := ""

	for _, line := range lines {
		if line == "" {
			if name != "" && version != "" {
				alpine.Packages = append(alpine.Packages, AlpinePackage{
					Name:    name,
					Version: version,
				})
				name = ""
				version = ""
			}
			continue
		}
		// TODO: be a bit more robust?
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("unexpected APK index line: %q", line)
		}
		if parts[0] == "P" {
			name = parts[1]
		} else if parts[0] == "V" {
			version = parts[1]
		}
	}
	return nil
}

func readGoMod(result *Result, reader io.Reader) error {
	// TODO: read better
	b, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read go.mod: %w", err)
	}

	// pull out the name of the module
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "module ") {
			if result.SourceCode == nil {
				result.SourceCode = &SourceCode{}
			}
			// TODO: add where it was found
			result.SourceCode.GoMod = append(result.SourceCode.GoMod, strings.TrimPrefix(line, "module "))
			break
		}
	}
	return nil
}

func scanDPKGStatus(debian *Debian, reader io.Reader) error {
	// TODO: do it in a streaming way
	b, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read dpkg/status status: %w", err)
	}
	lines := strings.Split(string(b), "\n")

	name := ""
	version := ""

	for _, line := range lines {
		if line == "" {
			if name != "" && version != "" {
				debian.Packages = append(debian.Packages, DebianPackage{
					Name:    name,
					Version: version,
				})
			}
			name = ""
			version = ""
			continue
		}
		if strings.HasPrefix(line, "Package: ") {
			name = strings.TrimPrefix(line, "Package: ")
		} else if strings.HasPrefix(line, "Version: ") {
			version = strings.TrimPrefix(line, "Version: ")
		}
	}

	return nil
}
