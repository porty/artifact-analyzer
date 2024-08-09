package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/porty/artifact-analyzer/registry"
	"github.com/porty/artifact-analyzer/scan"
)

func main() {
	r, err := registry.NewFileSystemRegistry("./registry-data")
	if err != nil {
		panic(err)
	}

	// distribution/distribution:latest
	// m, err := r.Manifest(registry.ManifestPath{
	// 	Path: "distribution/distribution",
	// 	Tag:  "latest",
	// })
	m, err := r.Manifest(registry.ManifestPath{
		Path: "library/debian",
		Tag:  "12-slim",
	})

	if err != nil {
		panic(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	for _, layer := range m.Layers {
		func() {
			digest := strings.TrimPrefix(layer.Digest, "sha256:")
			blob, err := r.Blob(digest)
			if err != nil {
				panic(err)
			}
			defer blob.Close()
			results, err := scan.ScanLayer(blob, layer.MediaType, digest)
			if err != nil {
				panic(err)
			}
			// log.Printf("Layer %s: %v", layer.Digest, results)
			// if err := scan.PrintResult(*results, os.Stdout); err != nil {
			// 	panic(err)
			// }
			if err := enc.Encode(results); err != nil {
				panic(err)
			}

		}()
	}
}
