package registry

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
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
