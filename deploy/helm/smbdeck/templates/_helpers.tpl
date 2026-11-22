{{/* Chart name. */}}
{{- define "smbdeck.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Full name: release-chart, or the release name when it already holds the chart name. */}}
{{- define "smbdeck.fullname" -}}
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

{{- define "smbdeck.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Labels common to every object. */}}
{{- define "smbdeck.labels" -}}
helm.sh/chart: {{ include "smbdeck.chart" . }}
app.kubernetes.io/name: {{ include "smbdeck.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: smbdeck
{{- end }}

{{/* Selector of the server pod (agent + web). */}}
{{- define "smbdeck.selectorLabels" -}}
app.kubernetes.io/name: {{ include "smbdeck.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end }}

{{/* Selector of the discovery pod. */}}
{{- define "smbdeck.discoverySelectorLabels" -}}
app.kubernetes.io/name: {{ include "smbdeck.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: discovery
{{- end }}

{{/* Image reference: repository:tag, or repository@digest when a digest is set. */}}
{{- define "smbdeck.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
{{- end }}

{{/* SMBDECK_ROOTS: name=/roots/name,... */}}
{{- define "smbdeck.roots" -}}
{{- $items := list }}
{{- range .Values.roots }}
{{- $items = append $items (printf "%s=/roots/%s" .name .name) }}
{{- end }}
{{- join "," $items }}
{{- end }}

{{/* Name of the state claim. */}}
{{- define "smbdeck.stateClaim" -}}
{{- default (printf "%s-state" (include "smbdeck.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}

{{/* Security context shared by the unprivileged containers. */}}
{{- define "smbdeck.restricted" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/* Environment of both discovery containers. */}}
{{- define "smbdeck.discoveryEnv" -}}
{{- $v := .ctx.Values.discovery -}}
- name: SMBDECK_DISCOVERY_HOSTNAME
  value: {{ .hostName | quote }}
{{- with $v.address }}
- name: SMBDECK_DISCOVERY_ADDRESS
  value: {{ . | quote }}
{{- end }}
{{- with $v.interface }}
- name: SMBDECK_DISCOVERY_INTERFACE
  value: {{ . | quote }}
{{- end }}
{{- with $v.displayName }}
- name: SMBDECK_DISCOVERY_NAME
  value: {{ . | quote }}
{{- end }}
- name: SMBDECK_DISCOVERY_WORKGROUP
  value: {{ $v.workgroup | quote }}
- name: SMBDECK_DISCOVERY_MODEL
  value: {{ $v.model | quote }}
{{- with $v.timeMachineShares }}
- name: SMBDECK_DISCOVERY_TIMEMACHINE_SHARES
  value: {{ join "," . | quote }}
{{- end }}
# tini is not PID 1 in a shared process namespace: register it as the
# subreaper of its children instead.
- name: TINI_SUBREAPER
  value: "1"
- name: SMBDECK_LOG_LEVEL
  value: {{ .ctx.Values.log.level | quote }}
- name: SMBDECK_LOG_FORMAT
  value: {{ .ctx.Values.log.format | quote }}
{{- end }}
