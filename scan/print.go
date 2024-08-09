package scan

import (
	"fmt"
	"io"
	"text/template"
)

const layerTemplate = `Layer {{.Digest}}
  Files: {{.FileCount}}
  Directories: {{.DirCount}}
  Size: {{ .Size | size }}
{{- if .Linux }}
  Linux {{ .Linux }}
{{- end }}
{{- if .Alpine }}
  Alpine
  {{- if .Alpine.Release }}
    Release {{ .Alpine.Release }}
  {{- end }}
  {{- if .Alpine.Packages }}
    Packages ({{ len .Alpine.Packages }}):
    {{- range .Alpine.Packages }}
      {{ .Name }}={{ .Version }}
    {{- end }}
  {{- end}}
{{- end }}
{{- if .Debian }}
  Debian
  {{- if .Debian.Release }}
    Release {{ .Debian.Release }}
  {{- end }}
  {{- if .Debian.Packages }}
    Packages ({{ len .Debian.Packages }}):
    {{- range .Debian.Packages }}
      {{ .Name }}={{ .Version }}
    {{- end }}
  {{- end}}
{{- end }}
{{- if .ELF }}
  ELF files:
  {{- range $key, $value := .ELF.Architectures }}
    {{$key}}: {{$value}}
  {{- end }}
{{- end }}
{{- if .SourceCode }}
  Source code: {{.SourceCode}}
{{- end }}
`

var layerCompiledTemplate = template.Must(template.New("layer").Funcs(template.FuncMap{
	"size": toHumanSize,
}).Parse(layerTemplate))

func PrintResult(result Result, w io.Writer) error {
	// tmpl, err := template.New("layer").Parse(layerTemplate)
	// if err != nil {
	// 	return err
	// }
	return layerCompiledTemplate.Execute(w, result)
}

func toHumanSize(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%d bytes", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%dKB", size/1024)
	}
	if size < 1024*1024*1024 {
		return fmt.Sprintf("%dMB", size/(1024*1024))
	}
	return fmt.Sprintf("%dGB", size/(1024*1024*1024))
}
