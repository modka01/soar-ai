import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { platform } from '@/api/resources';
import { Button, ErrorBanner, Spinner, Tag } from '@/components/primitives';
import { formatDateTime } from '@/lib/format';
import { toastError, useAuth, useToasts } from '@/lib/store';
import { AuditLog } from './AuditLog';
import { UsersPanel } from './UsersPanel';

/** Field definitions per namespace — labels, control type and help text. */
interface FieldSpec {
  key: string;
  label: string;
  type: 'text' | 'number' | 'password' | 'toggle' | 'select' | 'textarea';
  options?: string[];
  help?: string;
}

const SECTIONS: Record<string, { title: string; fields: FieldSpec[] }[]> = {
  general: [
    {
      title: 'Organisation',
      fields: [
        { key: 'org_name', label: 'Organisation name', type: 'text' },
        { key: 'platform_url', label: 'Platform URL', type: 'text' },
        {
          key: 'timezone',
          label: 'Time zone',
          type: 'select',
          options: [
            'UTC',
            'Asia/Kolkata',
            'America/New_York',
            'America/Los_Angeles',
            'Europe/London',
          ],
        },
      ],
    },
    {
      title: 'Session & authentication',
      fields: [
        { key: 'session_timeout_minutes', label: 'Session timeout (minutes)', type: 'number' },
        { key: 'max_login_attempts', label: 'Max failed logins before lockout', type: 'number' },
        {
          key: 'sso_provider',
          label: 'SSO provider',
          type: 'select',
          options: ['None', 'Okta', 'Azure AD', 'Google Workspace', 'SAML 2.0'],
        },
        { key: 'enforce_mfa', label: 'Enforce MFA for all users', type: 'toggle' },
      ],
    },
  ],
  agent: [
    {
      title: 'Model',
      fields: [
        {
          key: 'anthropic_api_key',
          label: 'Anthropic API key',
          type: 'password',
          help: 'Stored write-only. Reading it back returns a mask, never the value.',
        },
        { key: 'model', label: 'Model', type: 'text' },
        { key: 'max_tokens', label: 'Max tokens per turn', type: 'number' },
        { key: 'temperature', label: 'Temperature', type: 'text' },
        { key: 'max_iterations', label: 'Max agent iterations', type: 'number' },
      ],
    },
    {
      title: 'Agentic behaviour',
      fields: [
        {
          key: 'allow_destructive_actions',
          label: 'Allow destructive actions',
          type: 'toggle',
          help: 'When off, every mutating tool runs as a dry run and changes nothing.',
        },
        {
          key: 'require_approval_for_containment',
          label: 'Require approval for containment',
          type: 'toggle',
        },
        {
          key: 'auto_triage_threshold',
          label: 'Auto-triage confidence threshold (%)',
          type: 'number',
        },
        {
          key: 'auto_generate_sigma',
          label: 'Auto-generate Sigma on new incidents',
          type: 'toggle',
        },
      ],
    },
  ],
  rag: [
    {
      title: 'Retrieval',
      fields: [
        { key: 'chunk_size', label: 'Chunk size (tokens)', type: 'number' },
        { key: 'chunk_overlap', label: 'Chunk overlap (tokens)', type: 'number' },
        { key: 'top_k', label: 'Top-K retrieval', type: 'number' },
        {
          key: 'embedding_provider',
          label: 'Embedding provider',
          type: 'select',
          options: ['hashing', 'voyage', 'openai'],
        },
        { key: 'auto_index_incidents', label: 'Auto-index closed incidents', type: 'toggle' },
      ],
    },
  ],
  mcp: [
    {
      title: 'Tool permissions',
      fields: [
        { key: 'allow_query_siem', label: 'query_siem — SIEM searches', type: 'toggle' },
        { key: 'allow_enrich_ioc', label: 'enrich_ioc — external enrichment', type: 'toggle' },
        { key: 'allow_block_ip', label: 'block_ip — firewall changes', type: 'toggle' },
        { key: 'allow_isolate_host', label: 'isolate_host — endpoint isolation', type: 'toggle' },
        { key: 'allow_aws_remediate', label: 'aws_remediate — cloud changes', type: 'toggle' },
        { key: 'tool_call_logging', label: 'Log every tool call', type: 'toggle' },
      ],
    },
  ],
  n8n: [
    {
      title: 'Connection',
      fields: [
        { key: 'n8n_url', label: 'n8n host URL', type: 'text' },
        { key: 'n8n_api_key', label: 'n8n API key', type: 'password' },
        { key: 'webhook_base_url', label: 'Webhook base URL', type: 'text' },
        {
          key: 'workflow_timeout_seconds',
          label: 'Timeout per workflow (seconds)',
          type: 'number',
        },
      ],
    },
    {
      title: 'Automation',
      fields: [
        { key: 'auto_run_critical', label: 'Auto-run on Critical alerts', type: 'toggle' },
        { key: 'auto_run_high', label: 'Auto-run on High alerts', type: 'toggle' },
        { key: 'max_concurrent_workflows', label: 'Max concurrent workflows', type: 'number' },
      ],
    },
  ],
  alerting: [
    {
      title: 'Scoring and thresholds',
      fields: [
        { key: 'auto_close_threshold', label: 'Auto-close score threshold', type: 'number' },
        { key: 'auto_escalate_threshold', label: 'Auto-escalate score threshold', type: 'number' },
        { key: 'dedup_window_minutes', label: 'Deduplication window (minutes)', type: 'number' },
        { key: 'ai_risk_scoring', label: 'Enable AI risk scoring', type: 'toggle' },
        {
          key: 'correlate_into_incidents',
          label: 'Correlate alerts into incidents',
          type: 'toggle',
        },
      ],
    },
    {
      title: 'Suppression',
      fields: [
        { key: 'allowlisted_ips', label: 'Allowlisted IPs', type: 'text' },
        { key: 'allowlisted_users', label: 'Allowlisted users', type: 'text' },
      ],
    },
  ],
  aws: [
    {
      title: 'Access',
      fields: [
        { key: 'aws_account_id', label: 'Account ID', type: 'text' },
        {
          key: 'aws_role_arn',
          label: 'Role ARN (preferred)',
          type: 'text',
          help: 'Assume-role beats static keys — no long-lived credential to leak.',
        },
        { key: 'aws_region', label: 'Default region', type: 'text' },
      ],
    },
    {
      title: 'Services',
      fields: [
        { key: 'guardduty_enabled', label: 'GuardDuty', type: 'toggle' },
        { key: 'security_hub_enabled', label: 'Security Hub', type: 'toggle' },
        { key: 'macie_enabled', label: 'Macie', type: 'toggle' },
        {
          key: 'auto_remediate_low_risk',
          label: 'Auto-remediate low-risk findings',
          type: 'toggle',
        },
      ],
    },
  ],
  sigma: [
    {
      title: 'SIEM backends',
      fields: [
        { key: 'splunk_url', label: 'Splunk URL', type: 'text' },
        { key: 'splunk_token', label: 'Splunk token', type: 'password' },
        { key: 'elastic_url', label: 'Elasticsearch URL', type: 'text' },
        { key: 'elastic_api_key', label: 'Elastic API key', type: 'password' },
      ],
    },
    {
      title: 'Rule deployment',
      fields: [
        { key: 'auto_deploy_ai_rules', label: 'Auto-deploy AI-generated rules', type: 'toggle' },
        { key: 'review_period_hours', label: 'Review period (hours)', type: 'number' },
        { key: 'default_author', label: 'Default rule author', type: 'text' },
      ],
    },
  ],
  notify: [
    {
      title: 'Slack',
      fields: [
        { key: 'slack_webhook_url', label: 'Webhook URL', type: 'password' },
        { key: 'slack_channel', label: 'Default channel', type: 'text' },
      ],
    },
    {
      title: 'PagerDuty',
      fields: [
        { key: 'pagerduty_key', label: 'Integration key', type: 'password' },
        { key: 'page_on_critical_only', label: 'Page on Critical only', type: 'toggle' },
      ],
    },
    {
      title: 'Email (SMTP)',
      fields: [
        { key: 'smtp_host', label: 'SMTP host', type: 'text' },
        { key: 'smtp_port', label: 'SMTP port', type: 'number' },
        { key: 'smtp_password', label: 'SMTP password', type: 'password' },
        { key: 'critical_recipients', label: 'Critical recipients', type: 'text' },
      ],
    },
  ],
  api: [
    {
      title: 'Webhooks',
      fields: [
        {
          key: 'hmac_secret',
          label: 'Webhook HMAC secret',
          type: 'password',
          help: 'Signs alert ingestion and n8n callbacks. Rotating it invalidates existing senders.',
        },
        { key: 'verify_hmac', label: 'Verify HMAC signatures', type: 'toggle' },
        { key: 'rate_limit_per_minute', label: 'Rate limit (requests/min)', type: 'number' },
      ],
    },
  ],
  retention: [
    {
      title: 'Retention windows',
      fields: [
        { key: 'alert_retention_days', label: 'Alerts (days)', type: 'number' },
        { key: 'incident_retention_days', label: 'Incidents (days)', type: 'number' },
        {
          key: 'audit_retention_days',
          label: 'Audit log (days)',
          type: 'number',
          help: 'Audit entries are archived, never deleted by the platform.',
        },
        { key: 'agent_log_retention_days', label: 'Agent transcripts (days)', type: 'number' },
      ],
    },
  ],
  compliance: [
    {
      title: 'Frameworks',
      fields: [
        { key: 'soc2', label: 'SOC 2 Type II', type: 'toggle' },
        { key: 'iso27001', label: 'ISO 27001', type: 'toggle' },
        { key: 'nist_csf', label: 'NIST CSF', type: 'toggle' },
        { key: 'pci_dss', label: 'PCI-DSS 4.0', type: 'toggle' },
        { key: 'gdpr', label: 'GDPR / CCPA', type: 'toggle' },
      ],
    },
  ],
};

export function Settings() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);
  const canWrite = useAuth((state) => state.hasRole('admin'));
  const [active, setActive] = useState('general');
  const [draft, setDraft] = useState<Record<string, unknown>>({});

  const config = useQuery({ queryKey: ['settings'], queryFn: platform.settings });

  // Reset the working copy whenever the namespace or the server state changes,
  // so a half-edited form is never carried across tabs.
  useEffect(() => {
    setDraft(config.data?.settings[active] ?? {});
  }, [active, config.data]);

  const save = useMutation({
    mutationFn: () => platform.updateNamespace(active, draft),
    onSuccess: () => {
      push('Settings saved.');
      void queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
    onError: (error) => toastError(error, 'Could not save settings.'),
  });

  const exportConfig = useMutation({
    mutationFn: platform.exportSettings,
    onSuccess: (payload) => {
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `soar-config-${new Date().toISOString().slice(0, 10)}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      push('Configuration exported with secrets redacted.');
    },
    onError: (error) => toastError(error, 'Export failed.'),
  });

  if (config.isLoading) return <Spinner label="Loading platform settings…" />;
  if (config.error)
    return (
      <div className="scroll-area">
        <ErrorBanner error={config.error} onRetry={() => void config.refetch()} />
      </div>
    );

  const sections = SECTIONS[active];

  return (
    <div className="settings-shell">
      <div className="settings-nav">
        {config.data?.namespaces.map((namespace) => (
          <div
            className={`snav-item${namespace.key === active ? ' active' : ''}`}
            key={namespace.key}
            onClick={() => setActive(namespace.key)}
          >
            <span style={{ fontSize: 11 }}>{namespace.icon}</span>
            {namespace.label}
          </div>
        ))}
      </div>

      <div className="settings-content">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: 8,
            marginBottom: 18,
            paddingBottom: 14,
            borderBottom: '1px solid var(--br-light)',
          }}
        >
          {!canWrite && <Tag tone="amber">READ ONLY — administrator required</Tag>}
          <Button onClick={() => exportConfig.mutate()}>↓ Export config</Button>
          {sections && (
            <Button
              variant="gold"
              onClick={() => save.mutate()}
              disabled={!canWrite || save.isPending}
            >
              {save.isPending ? 'Saving…' : '✓ Save changes'}
            </Button>
          )}
        </div>

        {active === 'users' && <UsersPanel />}
        {active === 'audit' && <AuditLog />}

        {sections?.map((section) => (
          <div className="s-section" key={section.title}>
            <div className="s-section-title">{section.title}</div>
            {section.fields.map((field) => (
              <Field
                key={field.key}
                spec={field}
                value={draft[field.key]}
                disabled={!canWrite}
                onChange={(value) => setDraft({ ...draft, [field.key]: value })}
              />
            ))}
          </div>
        ))}

        {!sections && active !== 'users' && active !== 'audit' && (
          <div className="empty-state">
            <div className="empty-state-title">Nothing to configure here yet</div>
            <div>This namespace has no editable fields in this release.</div>
          </div>
        )}

        {config.data && (
          <div style={{ marginTop: 24, fontSize: 9.5, color: 'var(--tx-muted)' }}>
            Console v{__APP_VERSION__} · built {formatDateTime(__BUILD_TIME__)}
          </div>
        )}
      </div>
    </div>
  );
}

function Field({
  spec,
  value,
  disabled,
  onChange,
}: {
  spec: FieldSpec;
  value: unknown;
  disabled: boolean;
  onChange: (value: unknown) => void;
}) {
  const id = `setting-${spec.key}`;

  if (spec.type === 'toggle') {
    return (
      <div className="s-row">
        <label className="s-label" htmlFor={id}>
          {spec.label}
          {spec.help && <div className="s-help">{spec.help}</div>}
        </label>
        <label className="toggle">
          <input
            id={id}
            type="checkbox"
            checked={Boolean(value)}
            disabled={disabled}
            onChange={(event) => onChange(event.target.checked)}
          />
          <div className="toggle-track" />
        </label>
      </div>
    );
  }

  if (spec.type === 'select') {
    return (
      <div className="s-row">
        <label className="s-label" htmlFor={id}>
          {spec.label}
        </label>
        <select
          id={id}
          className="s-input-md"
          value={String(value ?? '')}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        >
          <option value="">—</option>
          {spec.options?.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </select>
      </div>
    );
  }

  if (spec.type === 'textarea') {
    return (
      <div className="s-field">
        <label className="s-label" htmlFor={id}>
          {spec.label}
        </label>
        <textarea
          id={id}
          className="s-input-wide"
          rows={3}
          value={String(value ?? '')}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        />
      </div>
    );
  }

  return (
    <div className="s-row">
      <label className="s-label" htmlFor={id}>
        {spec.label}
        {spec.help && <div className="s-help">{spec.help}</div>}
      </label>
      <input
        id={id}
        type={spec.type === 'password' ? 'password' : spec.type === 'number' ? 'number' : 'text'}
        className={spec.type === 'number' ? 's-input-sm' : 's-input-md'}
        value={String(value ?? '')}
        disabled={disabled}
        placeholder={spec.type === 'password' ? '••••••••' : undefined}
        onChange={(event) =>
          onChange(spec.type === 'number' ? Number(event.target.value) : event.target.value)
        }
      />
    </div>
  );
}
