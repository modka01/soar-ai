import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { alerts } from '@/api/resources';
import { Button, ErrorBanner, SeverityTag, Spinner, StatusTag, Tag } from '@/components/primitives';
import { relativeTime, truncate } from '@/lib/format';
import { toastError, useToasts } from '@/lib/store';
import type { Alert } from '@/types/api';

const FILTERS = ['All', 'critical', 'high', 'medium', 'low'];
const STATUSES = ['All', 'open', 'investigating', 'contained', 'automated', 'closed'];

export function AlertQueue() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);
  const [severity, setSeverity] = useState('All');
  const [status, setStatus] = useState('All');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Alert | null>(null);

  const query = useQuery({
    queryKey: ['alerts', severity, status, search],
    queryFn: () =>
      alerts.list({
        severity: severity === 'All' ? undefined : severity,
        status: status === 'All' ? undefined : status,
        search: search || undefined,
        limit: 100,
      }),
    refetchInterval: 30_000,
  });

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['alerts'] });

  const triage = useMutation({
    mutationFn: (id: string) => alerts.triage(id),
    onSuccess: (alert) => {
      push(`${alert.reference} triaged — risk ${alert.risk_score}`);
      invalidate();
    },
    onError: (error) => toastError(error, 'Triage failed.'),
  });

  const bulkTriage = useMutation({
    mutationFn: () => alerts.bulkTriage(25),
    onSuccess: (triaged) => {
      push(`Bulk triage complete — ${triaged.length} alert(s) scored.`);
      invalidate();
    },
    onError: (error) => toastError(error, 'Bulk triage failed.'),
  });

  const escalate = useMutation({
    mutationFn: (id: string) => alerts.escalate(id),
    onSuccess: (result) => {
      push(result.message);
      invalidate();
    },
    onError: (error) => toastError(error, 'Escalation failed.'),
  });

  const updateStatus = useMutation({
    mutationFn: ({ id, next }: { id: string; next: string }) => alerts.updateStatus(id, next),
    onSuccess: () => {
      push('Alert status updated.');
      invalidate();
    },
    onError: (error) => toastError(error, 'Could not update the alert.'),
  });

  return (
    <>
      <div className="filter-bar">
        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--tx-secondary)' }}>
          Severity
        </span>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          style={{ width: 'auto' }}
        >
          {FILTERS.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </select>
        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--tx-secondary)' }}>Status</span>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          style={{ width: 'auto' }}
        >
          {STATUSES.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </select>
        <input
          type="search"
          value={search}
          placeholder="Search alerts…"
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 220, fontSize: 10 }}
          aria-label="Search alerts"
        />
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 7 }}>
          <Button onClick={() => bulkTriage.mutate()} disabled={bulkTriage.isPending}>
            {bulkTriage.isPending ? 'Triaging…' : '⚡ Bulk AI triage'}
          </Button>
        </div>
      </div>

      <div className="scroll-area">
        {query.error && <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />}
        {query.isLoading ? (
          <Spinner label="Loading the alert queue…" />
        ) : (
          <div className="card">
            <table className="alert-tbl" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Source</th>
                  <th>Asset</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Seen</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {query.data?.items.length === 0 && (
                  <tr>
                    <td
                      colSpan={9}
                      style={{ textAlign: 'center', color: 'var(--tx-muted)', padding: 28 }}
                    >
                      No alerts match this filter.
                    </td>
                  </tr>
                )}
                {query.data?.items.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => setSelected(alert)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 9.5 }}>
                      {alert.reference}
                    </td>
                    <td>
                      <SeverityTag severity={alert.severity} />
                    </td>
                    <td style={{ fontWeight: 500 }}>
                      {truncate(alert.title, 60)}
                      {alert.duplicate_count > 0 && (
                        <Tag tone="gray" title="Duplicate detections folded into this alert">
                          ×{alert.duplicate_count + 1}
                        </Tag>
                      )}
                    </td>
                    <td style={{ color: 'var(--tx-muted)' }}>{alert.source}</td>
                    <td
                      style={{
                        color: 'var(--navy)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: 9.5,
                      }}
                    >
                      {alert.asset ?? '—'}
                    </td>
                    <td>
                      <StatusTag status={alert.status} />
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          color: alert.risk_score >= 80 ? 'var(--red)' : 'var(--tx-primary)',
                        }}
                      >
                        {alert.risk_score}
                      </span>
                      {alert.ai_triaged && (
                        <Tag tone="gold" title="Scored by the AI analyst">
                          AI
                        </Tag>
                      )}
                    </td>
                    <td style={{ color: 'var(--tx-muted)', fontSize: 9.5 }}>
                      {relativeTime(alert.detected_at)}
                    </td>
                    <td onClick={(event) => event.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <Button
                          onClick={() => triage.mutate(alert.id)}
                          disabled={triage.isPending}
                          style={{ fontSize: 9, padding: '2px 7px' }}
                          title="Score and summarise with the AI analyst"
                        >
                          Triage
                        </Button>
                        {!alert.incident_id && (
                          <Button
                            variant="navy"
                            onClick={() => escalate.mutate(alert.id)}
                            style={{ fontSize: 9, padding: '2px 7px' }}
                          >
                            Escalate
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {selected && (
          <div className="card card-navy-accent" style={{ marginTop: 14 }}>
            <div className="card-head">
              <span className="card-title">{selected.reference}</span>
              <SeverityTag severity={selected.severity} />
              <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                <select
                  value={selected.status}
                  onChange={(event) =>
                    updateStatus.mutate({ id: selected.id, next: event.target.value })
                  }
                  style={{ width: 'auto', fontSize: 10 }}
                  aria-label="Change alert status"
                >
                  {STATUSES.filter((s) => s !== 'All').map((option) => (
                    <option key={option}>{option}</option>
                  ))}
                </select>
                <Button onClick={() => setSelected(null)} style={{ fontSize: 9 }}>
                  Close
                </Button>
              </span>
            </div>
            <div className="card-body">
              <h3 style={{ fontSize: 13, color: 'var(--navy)', marginBottom: 6 }}>
                {selected.title}
              </h3>
              {selected.description && (
                <p style={{ fontSize: 11, color: 'var(--tx-secondary)', lineHeight: 1.7 }}>
                  {selected.description}
                </p>
              )}
              {selected.ai_summary && (
                <div className="highlight-box" style={{ marginTop: 10 }}>
                  <strong>✦ AI analyst</strong> — {selected.ai_summary}
                </div>
              )}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
                {selected.mitre_techniques.map((technique) => (
                  <Tag tone="navy" key={technique}>
                    {technique}
                  </Tag>
                ))}
                {selected.indicators.map((indicator) => (
                  <Tag tone="cyan" key={indicator}>
                    {indicator}
                  </Tag>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
