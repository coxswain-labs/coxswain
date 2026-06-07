{{/*
Expand the name of the chart.
*/}}
{{- define "coxswain.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated at 63 characters — Kubernetes DNS label limit.
When the release name already contains the chart name it is used as-is.
*/}}
{{- define "coxswain.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label: name-version (+ used in helm.sh/chart).
*/}}
{{- define "coxswain.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "coxswain.labels" -}}
helm.sh/chart: {{ include "coxswain.chart" . }}
{{ include "coxswain.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — stable subset used by Deployments and Services.
Version is intentionally excluded so rolling upgrades don't break selectors.
*/}}
{{- define "coxswain.selectorLabels" -}}
app.kubernetes.io/name: {{ include "coxswain.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name used by the Deployment.
*/}}
{{- define "coxswain.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "coxswain.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Actual container port for HTTP.
In rootless mode the container binds 8080 instead of the service port (default 80).
The gateway Service references this by name so the mapping is automatic.
*/}}
{{- define "coxswain.httpContainerPort" -}}
{{- if .Values.security.rootless -}}8080{{- else -}}{{ .Values.proxy.http.port }}{{- end -}}
{{- end }}

{{/*
Actual container port for HTTPS.
In rootless mode the container binds 8443 instead of the service port (default 443).
*/}}
{{- define "coxswain.httpsContainerPort" -}}
{{- if .Values.security.rootless -}}8443{{- else -}}{{ .Values.proxy.https.port }}{{- end -}}
{{- end }}
