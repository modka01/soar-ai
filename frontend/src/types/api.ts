/**
 * Types mirroring the backend's Pydantic schemas.
 *
 * Kept hand-written rather than generated so the console can be typechecked
 * without a running backend; the contract tests in `src/api/client.test.ts`
 * guard the shapes that matter.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertStatus =
  'open' | 'investigating' | 'contained' | 'automated' | 'closed' | 'false_positive';

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'eradicated' | 'closed';

export type AgentSessionStatus =
  'pending' | 'thinking' | 'executing' | 'awaiting_approval' | 'completed' | 'failed' | 'stopped';

export type RiskLevel = 'read_only' | 'low' | 'medium' | 'high' | 'critical';
export type HealthState = 'healthy' | 'degraded' | 'offline' | 'unknown';
export type ExecutionStatus = 'pending' | 'running' | 'success' | 'failed' | 'skipped' | 'dry_run';

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    details: Record<string, unknown>;
    request_id: string | null;
  };
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface Alert {
  id: string;
  reference: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: AlertStatus;
  source: string;
  asset: string | null;
  risk_score: number;
  confidence: number;
  ai_triaged: boolean;
  ai_summary: string | null;
  mitre_techniques: string[];
  indicators: string[];
  duplicate_count: number;
  detected_at: string;
  closed_at: string | null;
  incident_id: string | null;
  assignee: string | null;
  created_at: string;
}

export interface IncidentEvent {
  id: string;
  occurred_at: string;
  kind: string;
  actor: string;
  message: string;
  tool_name: string | null;
  severity: Severity | null;
  detail: Record<string, unknown>;
}

export interface Incident {
  id: string;
  reference: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: IncidentStatus;
  asset: string | null;
  owner: string | null;
  ai_summary: string | null;
  mitre_techniques: string[];
  indicators: string[];
  tags: string[];
  detected_at: string;
  contained_at: string | null;
  closed_at: string | null;
  external_ticket_id: string | null;
  external_ticket_url: string | null;
  created_at: string;
}

export interface IncidentDetail extends Incident {
  events: IncidentEvent[];
  alerts: Alert[];
  mttr_minutes: number | null;
}

export interface AgentMessage {
  id: string;
  sequence: number;
  role: 'user' | 'assistant' | 'system' | 'thought' | 'tool' | 'error';
  content: string;
  is_final: boolean;
  citations: RetrievalHit[];
  meta: Record<string, unknown>;
  created_at: string;
}

export interface AgentSession {
  id: string;
  task: string;
  status: AgentSessionStatus;
  created_by: string;
  model: string;
  iterations: number;
  max_iterations: number;
  plan: string[];
  plan_cursor: number;
  final_answer: string | null;
  error: string | null;
  input_tokens: number;
  output_tokens: number;
  incident_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface AgentSessionDetail extends AgentSession {
  messages: AgentMessage[];
}

export interface ProposedAction {
  tool: string;
  params: Record<string, unknown>;
  reason: string;
  risk: RiskLevel | 'unknown';
}

export interface Approval {
  id: string;
  session_id: string | null;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  reason: string;
  requested_actions: ProposedAction[];
  risk_score: number;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  expires_at: string;
  created_at: string;
}

export interface ToolSchema {
  name: string;
  label: string;
  description: string;
  category: string;
  risk: RiskLevel;
  icon: string;
  mutating: boolean;
  requires_approval: boolean;
  schema: {
    type: string;
    properties: Record<string, { type?: string; description?: string; enum?: string[] }>;
    required: string[];
  };
  calls: number;
  success_rate: number;
  avg_duration_ms: number;
  last_used_at: string | null;
}

export interface ToolExecution {
  id: string;
  tool_name: string;
  session_id: string | null;
  incident_id: string | null;
  invoked_by: string;
  reason: string | null;
  params: Record<string, unknown>;
  result: Record<string, unknown>;
  status: ExecutionStatus;
  error: string | null;
  duration_ms: number;
  dry_run: boolean;
  created_at: string;
}

export interface KnowledgeChunk {
  id: string;
  document_id: string | null;
  external_id: string | null;
  title: string;
  source: string;
  category: string;
  text: string;
  token_count: number;
  embedding_model: string;
}

export interface RetrievalHit {
  chunk_id: string;
  external_id?: string | null;
  title: string;
  source: string;
  category: string;
  text: string;
  score: number;
}

export interface RagStats {
  total_chunks: number;
  total_documents: number;
  avg_tokens_per_chunk: number;
  embedding_model: string;
  dimensions: number;
  chunk_size: number;
  chunk_overlap: number;
  top_k: number;
  by_source: { source: string; count: number }[];
  by_category: { category: string; count: number }[];
}

export interface SigmaRule {
  id: string;
  reference: string;
  rule_uuid: string;
  name: string;
  description: string | null;
  tactic: string;
  log_source: string;
  severity: Severity;
  status: string;
  yaml_body: string;
  mitre_techniques: string[];
  false_positives: string[];
  author: string;
  ai_generated: boolean;
  version: number;
  created_at: string;
}

export interface RuleDeployment {
  id: string;
  backend: string;
  converted_query: string;
  status: string;
  deployed_by: string;
  deployed_at: string | null;
  error: string | null;
}

export interface PlaybookStep {
  name: string;
  kind?: string;
  tool?: string;
  description?: string;
}

export interface Playbook {
  id: string;
  slug: string;
  name: string;
  description: string;
  severity: Severity;
  icon: string;
  estimated_seconds: number;
  enabled: boolean;
  requires_approval: boolean;
  steps: PlaybookStep[];
}

export interface PlaybookRunStep {
  index: number;
  name: string;
  kind?: string;
  status: ExecutionStatus;
  at: string;
  detail: Record<string, unknown>;
}

export interface PlaybookRun {
  id: string;
  playbook_id: string;
  incident_id: string | null;
  alert_id: string | null;
  status: ExecutionStatus;
  triggered_by: string;
  current_step: number;
  total_steps: number;
  step_results: PlaybookRunStep[];
  n8n_execution_id: string | null;
  error: string | null;
  dry_run: boolean;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface WorkflowNode {
  name: string;
  type: string;
  position?: [number, number];
}

export interface Workflow {
  id: string;
  name: string;
  active: boolean;
  tags: string[];
  updated_at: string | null;
  nodes: WorkflowNode[];
}

export interface ThreatIndicator {
  id: string;
  value: string;
  indicator_type: string;
  description: string | null;
  verdict: string;
  confidence: number;
  threat_actors: string[];
  mitre_techniques: string[];
  sources: string[];
  first_seen: string | null;
  last_seen: string | null;
}

export interface CloudFinding {
  id: string;
  provider: string;
  service: string;
  finding_type: string;
  title: string;
  description: string | null;
  severity: Severity;
  account_id: string | null;
  region: string | null;
  resource_id: string | null;
  resource_type: string | null;
  status: string;
  remediation: string | null;
  remediated_at: string | null;
  created_at: string;
}

export interface AwsServiceTile {
  name: string;
  icon: string;
  region: string;
  metrics: { label: string; value: string | number; tone: string }[];
}

export interface AwsOverview {
  account_id: string | null;
  region: string;
  services: AwsServiceTile[];
}

export interface IamRisk {
  principal: string;
  principal_type: string;
  risk: string;
  severity: Severity;
  remediation: string;
}

export interface Integration {
  slug: string;
  name: string;
  category: string;
  health: HealthState;
  latency_ms: number | null;
  last_checked_at: string | null;
  last_error: string | null;
}

export interface IntegrationHealth {
  total: number;
  healthy: number;
  degraded: number;
  offline: number;
  unknown: number;
  integrations: Integration[];
}

export interface AlertDistribution {
  window_hours: number;
  total: number;
  counts: Record<Severity, number>;
  automated: number;
  automation_rate: number;
}

export interface IncidentMetrics {
  window_days: number;
  open_incidents: number;
  critical_open: number;
  resolved: number;
  mttr_minutes: number | null;
  mttr_p90_minutes: number | null;
}

export interface ToolUsage {
  tool_name: string;
  calls: number;
  failures: number;
  success_rate: number;
  avg_duration_ms: number;
}

export interface DashboardMetrics {
  critical_alerts: number;
  open_incidents: number;
  auto_resolved: number;
  mttr_minutes: number | null;
  alert_distribution: AlertDistribution;
  incident_metrics: IncidentMetrics;
  integration_health: IntegrationHealth;
  tool_usage: ToolUsage[];
  recent_alerts: {
    id: string;
    reference: string;
    title: string;
    severity: Severity;
    status: AlertStatus;
    source: string;
    asset: string | null;
    risk_score: number;
    detected_at: string;
  }[];
}

export interface AuditEntry {
  id: string;
  actor: string;
  actor_type: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string;
  source_ip: string | null;
  request_id: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface SettingsNamespace {
  key: string;
  label: string;
  icon: string;
}

export interface SettingsPayload {
  namespaces: SettingsNamespace[];
  settings: Record<string, Record<string, unknown>>;
}

/** Events streamed by `GET /agent/sessions/{id}/stream`. */
export type AgentStreamEvent =
  | { type: 'context'; session_id: string; status: string; chunks: RetrievalHit[] }
  | { type: 'iteration'; session_id: string; status: string; iteration: number }
  | { type: 'plan'; session_id: string; status: string; steps: string[]; cursor: number }
  | { type: 'thought'; session_id: string; status: string; text: string }
  | { type: 'message'; session_id: string; status: string; text: string }
  | {
      type: 'tool_result';
      session_id: string;
      status: string;
      tool: string;
      ok: boolean;
      params?: Record<string, unknown>;
      reason?: string;
      result: Record<string, unknown>;
      duration_ms: number;
      dry_run?: boolean;
      execution_id?: string;
    }
  | {
      type: 'approval_required';
      session_id: string;
      status: string;
      approval_id: string;
      reason: string;
      actions: ProposedAction[];
      expires_at: string;
    }
  | { type: 'approval_decided'; approval_id: string; approved: boolean; by: string }
  | {
      type: 'final';
      session_id: string;
      status: string;
      answer: string;
      iterations?: number;
      tokens?: { input: number; output: number };
    }
  | { type: 'exhausted'; session_id: string; status: string; iterations: number }
  | { type: 'stopped'; session_id: string; status: string; by: string }
  | { type: 'error'; session_id?: string; status?: string; message: string }
  | { type: 'done' };
