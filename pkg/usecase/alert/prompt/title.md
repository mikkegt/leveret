このセキュリティアラートの短いタイトル（{{.MaxLength}}文字未満）を日本語で生成してください。前置きや説明は付けず、タイトルのみを返してください:

{{.AlertData}}
{{- if .FailedExamples}}

前回の試みは長すぎました（もっと短くしてください）:
{{- range .FailedExamples}}
- "{{.Title}}" ({{.Length}} 文字)
  {{- end}}
  {{- end}}