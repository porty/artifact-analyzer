package registry

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileSystemRegistryBlob(t *testing.T) {
	t.Run("invalid SHA256", func(t *testing.T) {
		r := FileSystemRegistry{}

		rc, err := r.Blob("fred")

		require.EqualError(t, err, "invalid SHA256: \"fred\"")
		require.Nil(t, rc)
	})
	t.Run("valid SHA256", func(t *testing.T) {
		r := FileSystemRegistry{
			fs: os.DirFS("../registry-data"),
		}

		t.Run("exists", func(t *testing.T) {
			// distribution/distribution:latest
			rc, err := r.Blob("ac79dfcbdc2a0bd00737e195a9aaafe1ec8b06682f970612f242acab0c8c925f")

			require.NoError(t, err)
			defer func() {
				err := rc.Close()
				require.NoError(t, err)
			}()

			b, err := io.ReadAll(rc)
			require.NoError(t, err)

			require.Equal(t, byte('{'), b[0])
			computedSHA256 := fmt.Sprintf("%x", sha256.Sum256(b))
			require.Equal(t, "ac79dfcbdc2a0bd00737e195a9aaafe1ec8b06682f970612f242acab0c8c925f", computedSHA256)
		})
		t.Run("doesn't exist", func(t *testing.T) {
			// distribution/distribution:latest
			rc, err := r.Blob("deadbeefdc2a0bd00737e195a9aaafe1ec8b06682f970612f242acab0c8c925f")
			require.EqualError(t, err, "failed to open blob \"deadbeefdc2a0bd00737e195a9aaafe1ec8b06682f970612f242acab0c8c925f\": open docker/registry/v2/blobs/sha256/de/deadbeefdc2a0bd00737e195a9aaafe1ec8b06682f970612f242acab0c8c925f/data: no such file or directory")
			require.Nil(t, rc)
		})
	})
}

func TestFileSystemRegistryManifest(t *testing.T) {
	r := FileSystemRegistry{
		fs: os.DirFS("../registry-data"),
	}

	t.Run("valid", func(t *testing.T) {
		// distribution/distribution:latest
		m, err := r.Manifest(ManifestPath{
			Path: "distribution/distribution",
			Tag:  "latest",
		})

		require.NoError(t, err)

		require.Equal(t, 2, m.SchemaVersion)
		require.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", m.MediaType)
	})
	t.Run("not found", func(t *testing.T) {
		// distribution/distribution:latest
		m, err := r.Manifest(ManifestPath{
			Path: "distribution/distribution",
			Tag:  "hello",
		})

		require.EqualError(t, err, "failed to open manifest link for distribution/distribution:hello: open docker/registry/v2/repositories/distribution/distribution/_manifests/tags/hello/current/link: no such file or directory")
		require.Nil(t, m)
	})
}

func TestIterateThroughManifestLayers(t *testing.T) {
	r := FileSystemRegistry{
		fs: os.DirFS("../registry-data"),
	}

	// distribution/distribution:latest
	m, err := r.Manifest(ManifestPath{
		Path: "distribution/distribution",
		Tag:  "latest",
	})

	require.NoError(t, err)

	for _, layer := range m.Layers {
		require.Equal(t, "application/vnd.docker.image.rootfs.diff.tar.gzip", layer.MediaType)
		readGzipLayer(t, &r, layer)
	}
	t.Fail()
}

func readGzipLayer(t *testing.T, fsr *FileSystemRegistry, layer Layer) {
	rc, err := fsr.Blob(strings.TrimPrefix(layer.Digest, "sha256:"))
	require.NoError(t, err)
	defer rc.Close()

	gr, err := gzip.NewReader(rc)
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		log.Printf("Name: %s", header.Name)
	}
}
