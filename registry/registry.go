package registry

import (
	"regexp"
)

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
	Layers []Layer `json:"layers"`
}

type Layer struct {
	MediaType string `json:"mediaType"`
	Size      int    `json:"size"`
	Digest    string `json:"digest"`
}

var (
	rawSHA256Regex      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	prefixedSHA256Regex = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)
	tagRegex            = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)
)
