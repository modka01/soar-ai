{{/* ── Naming ──────────────────────────────────────────────── */}}

{{- define "soar-ai.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "soar-ai.fullname" -}}
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

{{- define "soar-ai.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* ── Labels ──────────────────────────────────────────────── */}}

{{- define "soar-ai.labels" -}}
helm.sh/chart: {{ include "soar-ai.chart" . }}
{{ include "soar-ai.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: soar-ai
{{- with .Values.podLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "soar-ai.selectorLabels" -}}
app.kubernetes.io/name: {{ include "soar-ai.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Component-scoped labels — `component` is the tier name. */}}
{{- define "soar-ai.componentLabels" -}}
{{ include "soar-ai.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "soar-ai.componentSelectorLabels" -}}
{{ include "soar-ai.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* ── Images ──────────────────────────────────────────────── */}}

{{- define "soar-ai.backendImage" -}}
{{- $tag := .Values.image.backend.tag | default .Chart.AppVersion -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.backend.repository $tag -}}
{{- end -}}

{{- define "soar-ai.frontendImage" -}}
{{- $tag := .Values.image.frontend.tag | default .Chart.AppVersion -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.frontend.repository $tag -}}
{{- end -}}

{{/* ── Service account ─────────────────────────────────────── */}}

{{- define "soar-ai.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "soar-ai.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* ── Secrets ─────────────────────────────────────────────── */}}

{{/*
Resolve which Secret holds the sensitive configuration.
Precedence: an operator-supplied existing Secret, then one synced by External
Secrets, then one this chart creates for throwaway environments.
*/}}
{{- define "soar-ai.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else if .Values.externalSecrets.enabled -}}
{{- printf "%s-secrets" (include "soar-ai.fullname" .) -}}
{{- else -}}
{{- printf "%s-secrets" (include "soar-ai.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* ── Shared environment ──────────────────────────────────── */}}

{{/*
Environment shared by the API, the worker and the migration job, so all three
read exactly the same configuration.
*/}}
{{- define "soar-ai.commonEnv" -}}
- name: SOAR_ENVIRONMENT
  value: {{ .Values.config.environment | quote }}
- name: SOAR_LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: SOAR_LOG_FORMAT
  value: {{ .Values.config.logFormat | quote }}
- name: SOAR_CORS_ORIGINS
  value: {{ .Values.config.corsOrigins | quote }}
- name: SOAR_TRUSTED_HOSTS
  value: {{ .Values.config.trustedHosts | quote }}
- name: SOAR_RATE_LIMIT_PER_MINUTE
  value: {{ .Values.config.rateLimitPerMinute | quote }}
- name: SOAR_ANTHROPIC_MODEL
  value: {{ .Values.config.anthropic.model | quote }}
- name: SOAR_ANTHROPIC_MAX_TOKENS
  value: {{ .Values.config.anthropic.maxTokens | quote }}
- name: SOAR_ANTHROPIC_TEMPERATURE
  value: {{ .Values.config.anthropic.temperature | quote }}
- name: SOAR_AGENT_MAX_ITERATIONS
  value: {{ .Values.config.anthropic.agentMaxIterations | quote }}
- name: SOAR_EMBEDDING_PROVIDER
  value: {{ .Values.config.rag.embeddingProvider | quote }}
- name: SOAR_EMBEDDING_DIMENSIONS
  value: {{ .Values.config.rag.embeddingDimensions | quote }}
- name: SOAR_RAG_TOP_K
  value: {{ .Values.config.rag.topK | quote }}
- name: SOAR_RAG_CHUNK_SIZE
  value: {{ .Values.config.rag.chunkSize | quote }}
- name: SOAR_RAG_CHUNK_OVERLAP
  value: {{ .Values.config.rag.chunkOverlap | quote }}
- name: AWS_REGION
  value: {{ .Values.config.aws.region | quote }}
- name: SOAR_AWS_REGION
  value: {{ .Values.config.aws.region | quote }}
{{- with .Values.config.aws.accountId }}
- name: SOAR_AWS_ACCOUNT_ID
  value: {{ . | quote }}
{{- end }}
{{- with .Values.config.aws.roleArn }}
- name: SOAR_AWS_ROLE_ARN
  value: {{ . | quote }}
{{- end }}
- name: SOAR_N8N_URL
  value: {{ .Values.config.n8n.url | quote }}
- name: SOAR_ALLOW_DESTRUCTIVE_ACTIONS
  value: {{ .Values.config.safety.allowDestructiveActions | quote }}
- name: SOAR_REQUIRE_APPROVAL_FOR_CONTAINMENT
  value: {{ .Values.config.safety.requireApprovalForContainment | quote }}
- name: SOAR_APPROVAL_TIMEOUT_SECONDS
  value: {{ .Values.config.safety.approvalTimeoutSeconds | quote }}
- name: SOAR_METRICS_ENABLED
  value: {{ .Values.metrics.enabled | quote }}
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- end -}}

{{/*
Every secret value is injected by reference — no plaintext ever appears in a
manifest, a values file, or `helm get values`.
*/}}
{{- define "soar-ai.secretEnv" -}}
{{- $secret := include "soar-ai.secretName" . -}}
- name: SOAR_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: secret-key
- name: SOAR_WEBHOOK_HMAC_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: webhook-hmac-secret
- name: SOAR_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ .Values.postgresql.existingSecretKey }}
- name: SOAR_REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ .Values.redis.existingSecretKey }}
- name: SOAR_ANTHROPIC_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: anthropic-api-key
      optional: true
{{- range $env, $key := dict
    "SOAR_SPLUNK_TOKEN" "splunk-token"
    "SOAR_ELASTIC_API_KEY" "elastic-api-key"
    "SOAR_CROWDSTRIKE_CLIENT_ID" "crowdstrike-client-id"
    "SOAR_CROWDSTRIKE_CLIENT_SECRET" "crowdstrike-client-secret"
    "SOAR_VIRUSTOTAL_API_KEY" "virustotal-api-key"
    "SOAR_ABUSEIPDB_API_KEY" "abuseipdb-api-key"
    "SOAR_OTX_API_KEY" "otx-api-key"
    "SOAR_MISP_API_KEY" "misp-api-key"
    "SOAR_PALOALTO_API_KEY" "paloalto-api-key"
    "SOAR_JIRA_TOKEN" "jira-token"
    "SOAR_N8N_API_KEY" "n8n-api-key"
    "SOAR_SLACK_WEBHOOK_URL" "slack-webhook-url"
    "SOAR_PAGERDUTY_ROUTING_KEY" "pagerduty-routing-key"
    "SOAR_SMTP_PASSWORD" "smtp-password"
    "SOAR_VOYAGE_API_KEY" "voyage-api-key"
    "SOAR_BOOTSTRAP_ADMIN_PASSWORD" "bootstrap-admin-password"
}}
- name: {{ $env }}
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $key }}
      optional: true
{{- end }}
{{- end -}}

{{/*
A read-only root filesystem still needs scratch space: gunicorn's worker heartbeat
files and nginx's temp paths both live under /tmp.
*/}}
{{- define "soar-ai.tmpVolume" -}}
- name: tmp
  emptyDir:
    medium: Memory
    sizeLimit: 128Mi
{{- end -}}

{{- define "soar-ai.tmpVolumeMount" -}}
- name: tmp
  mountPath: /tmp
{{- end -}}
