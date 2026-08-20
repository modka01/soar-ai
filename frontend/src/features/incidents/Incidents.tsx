import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { incidents } from '@/api/resources';
import { Button, ErrorBanner, SeverityTag, Spinner, StatusTag, Tag } from '@/components/primitives';
import { formatDateTime, formatTime, relativeTime, renderMarkdown } from '@/lib/format';
import { toastError, useToasts } from '@/lib/store';

const SEVERITIES = ['All', 'critical', 'high', 'medium', 'low'];
const STATUSES = ['open', 'investigating', 'contained', 'eradicated', 'closed'];

export function Incidents() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);
  const [severity, setSeverity] = useState('All');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [note, setNote] = useState('');

  const list = useQuery({
    queryKey: ['incidents', severity],
    queryFn: () => incidents.list({ severity: severity === 'All' ? undefined : severity }),
    refetchInterval: 30_000,
  });

  const detail = useQuery({
    queryKey: ['incident', selectedId],
    queryFn: () => incidents.get(selectedId!),
    enabled: Boolean(selectedId),
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['incidents'] });
    void queryClient.invalidateQueries({ queryKey: ['incident', selectedId] });
  };

  const summarise = useMutation({
    mutationFn: (id: string) => incidents.generateSummary(id),
    onSuccess: () => {
      push('AI summary generated.');
      refresh();
    },
    onError: (error) => toastError(error, 'Could not generate the summary.'),
  });

  const setStatus = useMutation({
    mutationFn: ({ id, next }: { id: string; next: string }) => incidents.updateStatus(id, next),
    onSuccess: () => {
      push('Incident status updated.');
      refresh();
    },
    onError: (error) => toastError(error, 'Could not update the incident.'),
  });

  const addNote = useMutation({
    mutationFn: ({ id, message }: { id: string; message: string }) =>
      incidents.addEvent(id, message, 'note'),
    onSuccess: () => {
      setNote('');
      push('Timeline entry added.');
      refresh();
    },
    onError: (error) => toastError(error, 'Could not add the note.'),
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
          {SEVERITIES.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </select>
        <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--tx-muted)' }}>
          {list.data?.total ?? 0} case{list.data?.total === 1 ? '' : 's'}
        </span>
      </div>

      <div className="incident-shell">
        <div className="incident-list">
          {list.isLoading && <Spinner />}
          {list.error && <ErrorBanner error={list.error} onRetry={() => void list.refetch()} />}
          {list.data?.items.length === 0 && (
            <div className="empty-state">
              <div className="empty-state-title">No incidents</div>
              <div>Escalate an alert to open a case.</div>
            </div>
          )}
          {list.data?.items.map((incident) => (
            <div
              className={`inc-row${selectedId === incident.id ? ' selected' : ''}`}
              key={incident.id}
              onClick={() => setSelectedId(incident.id)}
            >
              <div
                className="inc-sev"
                style={{
                  background:
                    incident.severity === 'critical'
                      ? 'var(--red)'
                      : incident.severity === 'high'
                        ? 'var(--amber)'
                        : 'var(--blue)',
                }}
              />
              <div className="inc-body">
                <div className="inc-title">{incident.title}</div>
                <div className="inc-meta">
                  <SeverityTag severity={incident.severity} />
                  <StatusTag status={incident.status} />
                  <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
                    {incident.asset ?? '—'}
                  </span>
                  <span style={{ fontSize: 9, color: 'var(--tx-muted)', marginLeft: 'auto' }}>
                    {relativeTime(incident.detected_at)}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="incident-detail">
          {!selectedId && (
            <div className="empty-state">
              <div className="empty-state-title">Select an incident</div>
              <div>Pick a case to see its timeline and AI analysis.</div>
            </div>
          )}
          {detail.isLoading && selectedId && <Spinner />}
          {detail.data && (
            <>
              <div style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <span
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--navy)' }}
                  >
                    {detail.data.reference}
                  </span>
                  <SeverityTag severity={detail.data.severity} />
                  <StatusTag status={detail.data.status} />
                  <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                    <select
                      value={detail.data.status}
                      onChange={(event) =>
                        setStatus.mutate({ id: detail.data!.id, next: event.target.value })
                      }
                      style={{ width: 'auto', fontSize: 10 }}
                      aria-label="Change incident status"
                    >
                      {STATUSES.map((option) => (
                        <option key={option}>{option}</option>
                      ))}
                    </select>
                    <Button
                      variant="gold"
                      onClick={() => summarise.mutate(detail.data!.id)}
                      disabled={summarise.isPending}
                    >
                      {summarise.isPending ? 'Analysing…' : '✦ AI summary'}
                    </Button>
                  </span>
                </div>
                <h2 style={{ fontSize: 15, color: 'var(--navy)', fontFamily: 'var(--font-head)' }}>
                  {detail.data.title}
                </h2>
                <div style={{ fontSize: 10, color: 'var(--tx-muted)', marginTop: 4 }}>
                  Asset {detail.data.asset ?? '—'} · Owner {detail.data.owner ?? 'Unassigned'} ·
                  Detected {formatDateTime(detail.data.detected_at)}
                  {detail.data.mttr_minutes !== null &&
                    ` · Resolved in ${Math.round(detail.data.mttr_minutes)} min`}
                </div>
              </div>

              {detail.data.description && (
                <p
                  style={{
                    fontSize: 11.5,
                    color: 'var(--tx-secondary)',
                    lineHeight: 1.75,
                    marginBottom: 12,
                  }}
                >
                  {detail.data.description}
                </p>
              )}

              {detail.data.ai_summary && (
                <div className="highlight-box" style={{ marginBottom: 14 }}>
                  <strong>✦ AI analyst summary</strong>
                  <div
                    style={{ marginTop: 6 }}
                    dangerouslySetInnerHTML={{ __html: renderMarkdown(detail.data.ai_summary) }}
                  />
                </div>
              )}

              {detail.data.mitre_techniques.length > 0 && (
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 14 }}>
                  {detail.data.mitre_techniques.map((technique) => (
                    <Tag tone="navy" key={technique}>
                      {technique}
                    </Tag>
                  ))}
                </div>
              )}

              <div
                style={{
                  fontSize: 9,
                  color: 'var(--tx-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '1px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  marginBottom: 8,
                }}
              >
                Response timeline
              </div>
              <div className="timeline">
                {detail.data.events.map((event) => (
                  <div className="tl-item" key={event.id}>
                    <div
                      className="tl-dot"
                      style={{
                        background:
                          event.severity === 'critical'
                            ? 'var(--red)'
                            : event.kind === 'ai_summary'
                              ? 'var(--gold-deep)'
                              : 'var(--navy)',
                      }}
                    />
                    <div className="tl-content">
                      <div className="tl-time">
                        {formatTime(event.occurred_at)} · {event.actor}
                        {event.tool_name && ` · ${event.tool_name}`}
                      </div>
                      <div className="tl-text">{event.message}</div>
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 6, marginTop: 14 }}>
                <input
                  type="text"
                  value={note}
                  placeholder="Add a timeline note…"
                  onChange={(event) => setNote(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' && note.trim()) {
                      addNote.mutate({ id: detail.data!.id, message: note.trim() });
                    }
                  }}
                  style={{ flex: 1, fontSize: 11 }}
                  aria-label="Timeline note"
                />
                <Button
                  variant="navy"
                  onClick={() =>
                    note.trim() && addNote.mutate({ id: detail.data!.id, message: note.trim() })
                  }
                  disabled={!note.trim() || addNote.isPending}
                >
                  Add
                </Button>
              </div>

              {detail.data.alerts.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <div
                    style={{
                      fontSize: 9,
                      color: 'var(--tx-muted)',
                      textTransform: 'uppercase',
                      letterSpacing: '1px',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                      marginBottom: 8,
                    }}
                  >
                    Correlated alerts ({detail.data.alerts.length})
                  </div>
                  {detail.data.alerts.map((alert) => (
                    <div className="exec-row" key={alert.id}>
                      <SeverityTag severity={alert.severity} />
                      <span style={{ flex: 1, fontSize: 10.5 }}>{alert.title}</span>
                      <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>{alert.source}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
}
