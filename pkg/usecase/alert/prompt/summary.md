このセキュリティアラートについて、短いタイトルと詳細な説明を日本語で生成し、JSON形式で返してください。

# 要件:
- title: {{.MaxTitleLength}}文字未満であること
- description: 何が起きたのか、なぜ重要なのかを2〜3文で説明すること

# アラートデータ:
{{.AlertData}}
{{- if .FailedExamples}}

# 前回の試行は以下のエラーで失敗しました:
{{- range .FailedExamples}}
- {{.}}
  {{- end}}
  {{- end}}

"title" と "description" フィールドを持つJSONとして応答を返してください。
