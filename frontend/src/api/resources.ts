/** One typed function per backend endpoint, grouped by module. */

import { api, request, streamEvents } from './client';
import type {
  Alert,
  AlertDistribution,
  AgentSession,
  AgentSessionDetail,
  Approval,
  AuditEntry,
  AwsOverview,
  CloudFinding,
  DashboardMetrics,
  IamRisk,
  Incident,
  IncidentDetail,
  IncidentMetrics,
  Integration,
  KnowledgeChunk,
  Page,
  Playbook,
  PlaybookRun,
  RagStats,
  RetrievalHit,
  RuleDeployment,
  SettingsPayload,
  Severity,
  SigmaRule,
  ThreatIndicator,
  TokenPair,
  ToolExecution,
  ToolSchema,
  ToolUsage,
  User,
  Workflow,
} from '@/types/api';

// ── auth ────────────────────────────────────────────────────────────

export const auth = {
  login: (email: string, password: string) =>
    request<TokenPair>('/auth/login', {
      method: 'POST',
      body: { email, password },
      skipAuthRetry: true,
    }),
  me: () => api.get<User>('/auth/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post<{ message: string }>('/auth/password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),
  listUsers: (limit = 50, offset = 0) => api.get<Page<User>>('/users', { limit, offset }),
};

// ── dashboard ───────────────────────────────────────────────────────

export const dashboard = {
  metrics: (hours = 24) => api.get<DashboardMetrics>('/dashboard', { hours }),
  integrations: () => api.get<Integration[]>('/integrations'),
  probeIntegrations: () => api.post<{ probed: number }>('/integrations/probe'),
};

// ── agent ───────────────────────────────────────────────────────────

export const agent = {
  createTask: (task: string, incidentId?: string) =>
    api.post<AgentSession>('/agent/tasks', { task, incident_id: incidentId, stream: true }),
  listSessions: (limit = 50, offset = 0, status?: string) =>
    api.get<Page<AgentSession>>('/agent/sessions', { limit, offset, status }),
  getSession: (id: string) => api.get<AgentSessionDetail>(`/agent/sessions/${id}`),
  stop: (id: string) => api.post<AgentSession>(`/agent/sessions/${id}/stop`),
  /** Drives the loop server-side and streams progress back. */
  stream: (id: string, signal?: AbortSignal, follow = false) =>
    streamEvents(`/agent/sessions/${id}/stream`, { query: { follow }, signal }),
  listApprovals: (status = 'pending') =>
    api.get<Page<Approval>>('/agent/approvals', { status, limit: 50 }),
  decide: (approvalId: string, approved: boolean, note?: string) =>
    api.post<AgentSession>(`/agent/approvals/${approvalId}/decide`, { approved, note }),
};

// ── alerts ──────────────────────────────────────────────────────────

export const alerts = {
  list: (params: {
    severity?: string;
    status?: string;
    source?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }) => api.get<Page<Alert>>('/alerts', { limit: 50, offset: 0, ...params }),
  get: (id: string) => api.get<Alert>(`/alerts/${id}`),
  distribution: (hours = 24) => api.get<AlertDistribution>('/alerts/distribution', { hours }),
  triage: (id: string) => api.post<Alert>(`/alerts/${id}/triage`),
  bulkTriage: (limit = 25) => api.post<Alert[]>('/alerts/triage/bulk', { limit }),
  updateStatus: (id: string, status: string) =>
    api.patch<Alert>(`/alerts/${id}/status`, { status }),
  escalate: (id: string) =>
    api.post<{ message: string; detail?: Record<string, unknown> }>(`/alerts/${id}/escalate`),
};

// ── incidents ───────────────────────────────────────────────────────

export const incidents = {
  list: (params: { severity?: string; status?: string; limit?: number; offset?: number }) =>
    api.get<Page<Incident>>('/incidents', { limit: 50, offset: 0, ...params }),
  get: (id: string) => api.get<IncidentDetail>(`/incidents/${id}`),
  metrics: (days = 30) => api.get<IncidentMetrics>('/incidents/metrics', { days }),
  create: (payload: {
    title: string;
    severity: Severity;
    description?: string;
    asset?: string;
    alert_ids?: string[];
  }) => api.post<Incident>('/incidents', payload),
  updateStatus: (id: string, status: string) =>
    api.patch<Incident>(`/incidents/${id}/status`, { status }),
  addEvent: (id: string, message: string, kind = 'note') =>
    api.post(`/incidents/${id}/events`, { message, kind }),
  generateSummary: (id: string) => api.post<IncidentDetail>(`/incidents/${id}/summary`),
};

// ── MCP tools ───────────────────────────────────────────────────────

export const mcp = {
  listTools: () => api.get<ToolSchema[]>('/mcp/tools'),
  getTool: (name: string) => api.get<ToolSchema>(`/mcp/tools/${name}`),
  invoke: (name: string, params: Record<string, unknown>, dryRun = false) =>
    api.post<ToolExecution>(`/mcp/tools/${name}/invoke`, { params, dry_run: dryRun }),
  executions: (limit = 50, offset = 0, toolName?: string) =>
    api.get<Page<ToolExecution>>('/mcp/executions', { limit, offset, tool_name: toolName }),
  stats: () => api.get<ToolUsage[]>('/mcp/stats'),
};

// ── RAG ─────────────────────────────────────────────────────────────

export const rag = {
  chunks: (params: { search?: string; category?: string; limit?: number; offset?: number }) =>
    api.get<Page<KnowledgeChunk>>('/rag/chunks', { limit: 100, offset: 0, ...params }),
  retrieve: (query: string, topK = 4) =>
    api.post<RetrievalHit[]>('/rag/retrieve', { query, top_k: topK }),
  stats: () => api.get<RagStats>('/rag/stats'),
  addDocument: (payload: {
    title: string;
    source: string;
    category: string;
    content: string;
    url?: string;
  }) => api.post('/rag/documents', payload),
  deleteDocument: (id: string) => api.delete(`/rag/documents/${id}`),
};

// ── Sigma ───────────────────────────────────────────────────────────

export const sigma = {
  list: (params: { search?: string; tactic?: string; severity?: string; limit?: number }) =>
    api.get<Page<SigmaRule>>('/sigma/rules', { limit: 100, ...params }),
  get: (id: string) => api.get<SigmaRule>(`/sigma/rules/${id}`),
  generate: (payload: {
    scenario: string;
    tactic: string;
    log_source: string;
    severity: Severity;
    use_ai: boolean;
  }) => api.post<SigmaRule>('/sigma/generate', payload),
  validate: (yamlBody: string) =>
    api.post<{ valid: boolean; title: string; level: string }>('/sigma/validate', {
      yaml_body: yamlBody,
    }),
  convert: (yamlBody: string, backend: string) =>
    api.post<{ backend: string; query: string }>('/sigma/convert', {
      yaml_body: yamlBody,
      backend,
    }),
  update: (id: string, yamlBody: string) =>
    api.put<SigmaRule>(`/sigma/rules/${id}`, { yaml_body: yamlBody }),
  deploy: (id: string, backends: string[]) =>
    api.post<RuleDeployment[]>(`/sigma/rules/${id}/deploy`, { backends }),
  backends: () => api.get<{ backends: string[] }>('/sigma/backends'),
};

// ── AWS ─────────────────────────────────────────────────────────────

export const aws = {
  overview: (region?: string) => api.get<AwsOverview>('/aws/overview', { region }),
  findings: (params: { service?: string; severity?: string; limit?: number }) =>
    api.get<Page<CloudFinding>>('/aws/findings', { limit: 50, ...params }),
  sync: (region?: string) => api.post<{ message: string }>('/aws/sync', undefined, { region }),
  iamRisks: () => api.get<{ total: number; critical: number; risks: IamRisk[] }>('/aws/iam-risks'),
  publicBuckets: () =>
    api.get<{ total: number; buckets: { bucket: string; reason: string }[] }>(
      '/aws/public-buckets',
    ),
  remediate: (action: string, resourceId: string, reason: string) =>
    api.post('/aws/remediate', { action, resource_id: resourceId, reason }),
};

// ── playbooks and workflows ─────────────────────────────────────────

export const playbooks = {
  list: () => api.get<Playbook[]>('/playbooks'),
  get: (id: string) => api.get<Playbook>(`/playbooks/${id}`),
  stats: () =>
    api.get<{ slug: string; name: string; runs: number; success_rate: number }[]>(
      '/playbooks/stats',
    ),
  run: (id: string, payload: { incident_id?: string; alert_id?: string; dry_run?: boolean } = {}) =>
    api.post<PlaybookRun>(`/playbooks/${id}/run`, payload),
  runs: (limit = 50, playbookId?: string) =>
    api.get<Page<PlaybookRun>>('/playbook-runs', { limit, playbook_id: playbookId }),
  getRun: (id: string) => api.get<PlaybookRun>(`/playbook-runs/${id}`),
};

export const workflows = {
  list: (activeOnly = false) => api.get<Workflow[]>('/workflows', { active_only: activeOnly }),
  get: (id: string) => api.get<Workflow>(`/workflows/${id}`),
  runs: (limit = 50) => api.get<Page<Record<string, unknown>>>('/workflow-runs', { limit }),
};

// ── threat intel ────────────────────────────────────────────────────

export const threats = {
  feed: (limit = 50, minConfidence = 0) =>
    api.get<ThreatIndicator[]>('/threats/feed', { limit, min_confidence: minConfidence }),
  stats: () =>
    api.get<{
      total: number;
      by_verdict: Record<string, number>;
      by_type: Record<string, number>;
      top_actors: { actor: string; count: number }[];
    }>('/threats/stats'),
  enrich: (value: string, force = false) =>
    api.post<ThreatIndicator>('/threats/enrich', { value, force }),
};

// ── settings and audit ──────────────────────────────────────────────

export const platform = {
  settings: () => api.get<SettingsPayload>('/settings'),
  namespace: (ns: string) => api.get<Record<string, unknown>>(`/settings/${ns}`),
  updateNamespace: (ns: string, values: Record<string, unknown>) =>
    api.put<Record<string, unknown>>(`/settings/${ns}`, { values }),
  exportSettings: () => api.get<SettingsPayload>('/settings-export'),
  audit: (params: { search?: string; action?: string; limit?: number; offset?: number }) =>
    api.get<Page<AuditEntry>>('/audit', { limit: 100, offset: 0, ...params }),
};
