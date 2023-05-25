{{/*
Expand the name of the chart.
*/}}
{{- define "aws-secrets-synchronizer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "aws-secrets-synchronizer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "aws-secrets-synchronizer.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "aws-secrets-synchronizer.labels" -}}
helm.sh/chart: {{ include "aws-secrets-synchronizer.chart" . }}
{{ include "aws-secrets-synchronizer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/part-of: {{ template "aws-secrets-synchronizer.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.commonLabels}}
{{ toYaml .Values.commonLabels }}
{{- end }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "aws-secrets-synchronizer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aws-secrets-synchronizer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "aws-secrets-synchronizer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "aws-secrets-synchronizer.name" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Create the name of the cluster role to use
*/}}
{{- define "aws-secrets-synchronizer.clusterRoleName" -}}
{{ default (include "aws-secrets-synchronizer.name" .) .Values.clusterRole.name }}
{{- end -}}

{{/*
Create the name of the cluster role binding to use
*/}}
{{- define "aws-secrets-synchronizer.clusterRoleBindingName" -}}
{{ printf "%s-%s" (include "aws-secrets-synchronizer.clusterRoleName" .) "role-binding" }}
{{- end -}}
