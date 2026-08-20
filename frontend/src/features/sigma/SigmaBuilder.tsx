import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { sigma } from '@/api/resources';
import { Button, ErrorBanner, SeverityTag, Spinner, Tag } from '@/components/primitives';
import { Modal } from '@/components/Modal';
import { relativeTime } from '@/lib/format';
import { toastError, useToasts } from '@/lib/store';
import type { Severity, SigmaRule } from '@/types/api';

const LOG_SOURCES = [
  'Windows EventLog',
  'Sysmon',
  'AWS CloudTrail',
  'Linux Auditd',
  'Azure AD',
  'DNS',
  'Network/Firewall',
];

const TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export function SigmaBuilder() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);

  const [scenario, setScenario] = useState('');
  const [tactic, setTactic] = useState('Lateral Movement');
  const [logSource, setLogSource] = useState('Windows EventLog');
  const [severity, setSeverity] = useState<Severity>('high');
  const [useAi, setUseAi] = useState(true);
  const [selected, setSelected] = useState<SigmaRule | null>(null);
  const [yamlDraft, setYamlDraft] = useState('');
  const [converted, setConverted] = useState<{ backend: string; query: string } | null>(null);
  const [deploying, setDeploying] = useState(false);
  const [targets, setTargets] = useState<string[]>(['splunk']);
  const [search, setSearch] = useState('');

  const rules = useQuery({
    queryKey: ['sigma', 'rules', search],
    queryFn: () => sigma.list({ search: search || undefined }),
  });
  const backends = useQuery({ queryKey: ['sigma', 'backends'], queryFn: sigma.backends });

  const generate = useMutation({
    mutationFn: () =>
      sigma.generate({ scenario, tactic, log_source: logSource, severity, use_ai: useAi }),
    onSuccess: (rule) => {
      setSelected(rule);
      setYamlDraft(rule.yaml_body);
      setConverted(null);
      push(`${rule.reference} generated as a draft.`);
      void queryClient.invalidateQueries({ queryKey: ['sigma'] });
    },
    onError: (error) => toastError(error, 'Rule generation failed.'),
  });

  const save = useMutation({
    mutationFn: () => sigma.update(selected!.id, yamlDraft),
    onSuccess: (rule) => {
      setSelected(rule);
      push(`${rule.reference} saved as version ${rule.version}.`);
      void queryClient.invalidateQueries({ queryKey: ['sigma'] });
    },
    onError: (error) => toastError(error, 'The rule did not validate.'),
  });

  const convert = useMutation({
    mutationFn: (backend: string) => sigma.convert(yamlDraft, backend),
    onSuccess: setConverted,
    onError: (error) => toastError(error, 'Conversion failed.'),
  });

  const deploy = useMutation({
    mutationFn: () => sigma.deploy(selected!.id, targets),
    onSuccess: (deployments) => {
      const ok = deployments.filter((d) => d.status === 'converted').length;
      push(`Deployed to ${ok} of ${deployments.length} backend(s).`);
      setDeploying(false);
      void queryClient.invalidateQueries({ queryKey: ['sigma'] });
    },
    onError: (error) => toastError(error, 'Deployment failed.'),
  });

  return (
    <>
      <div className="filter-bar" style={{ flexWrap: 'wrap' }}>
        <select
          value={logSource}
          onChange={(e) => setLogSource(e.target.value)}
          style={{ width: 'auto' }}
        >
          {LOG_SOURCES.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </select>
        <select
          value={tactic}
          onChange={(e) => setTactic(e.target.value)}
          style={{ width: 'auto' }}
        >
          {TACTICS.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Severity)}
          style={{ width: 'auto' }}
        >
          {SEVERITIES.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </select>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            fontSize: 10,
            color: 'var(--tx-secondary)',
          }}
        >
          <input type="checkbox" checked={useAi} onChange={(e) => setUseAi(e.target.checked)} />
          Author with AI
        </label>
        <Button
          variant="navy"
          onClick={() => generate.mutate()}
          disabled={!scenario.trim() || generate.isPending}
        >
          {generate.isPending ? 'Generating…' : '✦ Generate rule'}
        </Button>
        {selected && (
          <>
            <Button onClick={() => save.mutate()} disabled={save.isPending}>
              Save
            </Button>
            <Button
              onClick={() => {
                void navigator.clipboard?.writeText(yamlDraft);
                push('Rule copied to the clipboard.');
              }}
            >
              ⎘ Copy
            </Button>
            <Button variant="gold" onClick={() => setDeploying(true)}>
              → Deploy
            </Button>
          </>
        )}
      </div>

      <div className="sigma-layout" style={{ padding: 16, flex: 1, overflow: 'hidden' }}>
        <div className="sigma-col">
          <ColumnLabel>Scenario</ColumnLabel>
          <textarea
            value={scenario}
            onChange={(event) => setScenario(event.target.value)}
            placeholder="Describe the attack behaviour, or paste the IOC / log evidence to detect…"
            style={{
              width: '100%',
              minHeight: 72,
              resize: 'vertical',
              marginBottom: 10,
              fontSize: 11,
              borderRadius: 'var(--r)',
              border: '1.5px solid var(--br-mid)',
            }}
            aria-label="Detection scenario"
          />

          <ColumnLabel>
            {selected ? `${selected.reference} · ${selected.name}` : 'Generated rule'}
          </ColumnLabel>
          <textarea
            className="sigma-editor"
            value={yamlDraft}
            spellCheck={false}
            onChange={(event) => setYamlDraft(event.target.value)}
            placeholder="The generated Sigma YAML appears here and is editable before deployment."
            aria-label="Sigma rule YAML"
            style={{ resize: 'none' }}
          />

          {selected && (
            <div style={{ display: 'flex', gap: 5, marginTop: 8, flexWrap: 'wrap' }}>
              {(backends.data?.backends ?? []).map((backend) => (
                <Button
                  key={backend}
                  onClick={() => convert.mutate(backend)}
                  style={{ fontSize: 9 }}
                >
                  Preview {backend}
                </Button>
              ))}
            </div>
          )}

          {converted && (
            <div style={{ marginTop: 10 }}>
              <ColumnLabel>{converted.backend} query</ColumnLabel>
              <pre
                style={{
                  background: 'var(--bg-sunken)',
                  border: '1px solid var(--br-mid)',
                  borderRadius: 'var(--r)',
                  padding: 10,
                  fontSize: 10,
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--navy)',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  maxHeight: 140,
                  overflowY: 'auto',
                }}
              >
                {converted.query}
              </pre>
            </div>
          )}
        </div>

        <div className="sigma-col">
          <ColumnLabel>Rule library ({rules.data?.total ?? 0})</ColumnLabel>
          <input
            type="search"
            value={search}
            placeholder="Search rules…"
            onChange={(event) => setSearch(event.target.value)}
            style={{ width: '100%', marginBottom: 8, fontSize: 10 }}
            aria-label="Search rules"
          />
          <div
            style={{
              flex: 1,
              overflowY: 'auto',
              border: '1.5px solid var(--br-mid)',
              borderRadius: 'var(--r2)',
              background: 'var(--bg-surface)',
            }}
          >
            {rules.error && (
              <ErrorBanner error={rules.error} onRetry={() => void rules.refetch()} />
            )}
            {rules.isLoading && <Spinner />}
            {rules.data?.items.length === 0 && (
              <div className="empty-state">
                <div className="empty-state-title">No rules yet</div>
                <div>Describe a scenario and generate your first detection.</div>
              </div>
            )}
            {rules.data?.items.map((rule) => (
              <div
                className="rule-row"
                key={rule.id}
                onClick={() => {
                  setSelected(rule);
                  setYamlDraft(rule.yaml_body);
                  setConverted(null);
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="rule-name">{rule.name}</div>
                  <div className="rule-meta">
                    {rule.reference} · {rule.tactic} · {rule.log_source}
                    {rule.ai_generated && ' · AI'}
                  </div>
                </div>
                <SeverityTag severity={rule.severity} />
                <Tag tone={rule.status === 'stable' ? 'green' : 'gray'}>{rule.status}</Tag>
                <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
                  {relativeTime(rule.created_at)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <Modal
        open={deploying}
        title="Deploy detection rule"
        onClose={() => setDeploying(false)}
        onConfirm={() => deploy.mutate()}
        confirmLabel="Deploy"
        confirmVariant="gold"
        busy={deploy.isPending}
      >
        <p
          style={{ fontSize: 11, color: 'var(--tx-secondary)', marginBottom: 12, lineHeight: 1.7 }}
        >
          The rule is converted for each backend and the resulting query is recorded, whether or not
          that SIEM&apos;s API is reachable — so you always get a query you can paste.
        </p>
        {(backends.data?.backends ?? []).map((backend) => (
          <div className="s-row" key={backend}>
            <label className="s-label" htmlFor={`backend-${backend}`}>
              {backend}
            </label>
            <label className="toggle">
              <input
                id={`backend-${backend}`}
                type="checkbox"
                checked={targets.includes(backend)}
                onChange={(event) =>
                  setTargets(
                    event.target.checked
                      ? [...targets, backend]
                      : targets.filter((item) => item !== backend),
                  )
                }
              />
              <div className="toggle-track" />
            </label>
          </div>
        ))}
      </Modal>
    </>
  );
}

function ColumnLabel({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 9,
        color: 'var(--tx-muted)',
        textTransform: 'uppercase',
        letterSpacing: '1px',
        marginBottom: 6,
        fontFamily: 'var(--font-mono)',
        fontWeight: 700,
      }}
    >
      {children}
    </div>
  );
}
