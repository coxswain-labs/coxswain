{{/*
Expand the name of the chart.
*/}}
{{- define "coxswain.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace every resource is deployed into.
Defaults to the release namespace (the `helm --namespace` value), with an
optional `namespaceOverride` escape hatch — the idiomatic pattern shared by
ingress-nginx, cert-manager, Traefik, and Envoy Gateway. Never hardcode a
namespace in a template; always render this helper so `helm --namespace` is
honoured and every resource resolves to one consistent namespace.
*/}}
{{- define "coxswain.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride | trunc 63 | trimSuffix "-" }}
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
Controller pod fullname: "<release>-coxswain-controller".
*/}}
{{- define "coxswain.controller.fullname" -}}
{{- printf "%s-controller" (include "coxswain.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Shared-proxy pod fullname: "<release>-coxswain-shared-proxy".
*/}}
{{- define "coxswain.sharedProxy.fullname" -}}
{{- printf "%s-shared-proxy" (include "coxswain.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Discovery Service name. Fixed (not release-prefixed) because the controller's
operator renders this exact DNS name into dedicated-proxy `--discovery-endpoint`
args, and the shared-proxy endpoint env is derived from the same helper so both
agree. The Service is namespaced, so distinct installs in distinct namespaces do
not collide.
*/}}
{{- define "coxswain.discovery.serviceName" -}}
coxswain-controller-discovery
{{- end }}

{{/*
Controller selector labels — selectorLabels + component=controller.
*/}}
{{- define "coxswain.controller.selectorLabels" -}}
{{ include "coxswain.selectorLabels" . }}
app.kubernetes.io/component: controller
{{- end }}

{{/*
Shared-proxy selector labels — selectorLabels + component=shared-proxy.
*/}}
{{- define "coxswain.sharedProxy.selectorLabels" -}}
{{ include "coxswain.selectorLabels" . }}
app.kubernetes.io/component: shared-proxy
{{- end }}

{{/*
Controller ServiceAccount name.
*/}}
{{- define "coxswain.controller.serviceAccountName" -}}
{{- if .Values.controller.serviceAccount.create }}
{{- default (include "coxswain.controller.fullname" .) .Values.controller.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.controller.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Shared-proxy ServiceAccount name.
*/}}
{{- define "coxswain.sharedProxy.serviceAccountName" -}}
{{- if .Values.proxy.shared.serviceAccount.create }}
{{- default (include "coxswain.sharedProxy.fullname" .) .Values.proxy.shared.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.proxy.shared.serviceAccount.name }}
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
