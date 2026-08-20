import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { playbooks } from '@/api/resources';
import {
  Button,
  Card,
  ErrorBanner,
  ProgressBar,
  SeverityTag,
  Spinner,
  Tag,
} from '@/components/primitives';
import { formatTime, relativeTime } from '@/lib/format';
import { toastError, useToasts } from '@/lib/store';
import type { Playbook, PlaybookRun } from '@/types/api';

export function Playbooks() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);
  const [activeRun, setActiveRun] = useState<PlaybookRun | null>(null);

  const list = useQuery({ queryKey: ['playbooks'], queryFn: playbooks.list });
  const stats = useQuery({ queryKey: ['playbooks', 'stats'], queryFn: playbooks.stats });
  const runs = useQuery({
    queryKey: ['playbook-runs'],
    queryFn: () => playbooks.runs(20),
    refetchInterval: 15_000,
  });

  // A dispatched run reports progress through the n8n callback, so poll the
  // one the operator just started until it reaches a terminal state.
  const liveRun = useQuery({
    queryKey: ['playbook-run', activeRun?.id],
    queryFn: () => playbooks.getRun(activeRun!.id),
    enabled: Boolean(activeRun && activeRun.status === 'running'),
    refetchInterval: 3000,
  });

  const run = useMutation({
    mutationFn: (playbook: Playbook) => playbooks.run(playbook.slug),
    onSuccess: (result) => {
      setActiveRun(result);
      push(
        result.dry_run
          ? 'Playbook executed as a dry run — no live actions were taken.'
          : 'Playbook dispatched to n8n.',
        result.dry_run ? 'warning' : 'success',
      );
      void queryClient.invalidateQueries({ queryKey: ['playbook-runs'] });
    },
    onError: (error) => toastError(error, 'Could not start the playbook.'),
  });

  const shown = liveRun.data ?? activeRun;
  const statsBySlug = new Map((stats.data ?? []).map((entry) => [entry.slug, entry]));

  return (
    <div className="scroll-area">
      <div className="highlight-box">
        <strong>✦ QuantNexa playbook engine</strong> — every playbook executes through n8n with AI
        enrichment. Each step is logged and auditable, and playbooks marked as gated require a human
        decision before any containment step runs.
      </div>

      {list.error && <ErrorBanner error={list.error} onRetry={() => void list.refetch()} />}
      {list.isLoading ? (
        <Spinner label="Loading playbooks…" />
      ) : (
        <div className="playbook-grid">
          {list.data?.map((playbook) => {
            const stat = statsBySlug.get(playbook.slug);
            return (
              <div className="playbook-card" key={playbook.id}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                  <span style={{ fontSize: 16 }}>{playbook.icon}</span>
                  <div className="pb-name">{playbook.name}</div>
                  <span style={{ marginLeft: 'auto' }}>
                    <SeverityTag severity={playbook.severity} />
                  </span>
                </div>
                <div className="pb-desc">{playbook.description}</div>
                {shown?.playbook_id === playbook.id && (
                  <ProgressBar
                    percent={shown.total_steps ? (shown.current_step / shown.total_steps) * 100 : 0}
                    tone={shown.status === 'failed' ? 'red' : 'navy'}
                  />
                )}
                <div className="pb-meta">
                  <Tag tone="cyan">n8n</Tag>
                  {playbook.requires_approval && <Tag tone="amber">GATED</Tag>}
                  <span className="pb-steps">{playbook.steps.length} steps</span>
                  <span>~{Math.round(playbook.estimated_seconds / 60)} min</span>
                  {stat && stat.runs > 0 && (
                    <span style={{ color: 'var(--tx-muted)' }}>
                      {stat.runs} runs · {stat.success_rate}%
                    </span>
                  )}
                  <span style={{ marginLeft: 'auto' }}>
                    <Button
                      variant="navy"
                      style={{ fontSize: 9, padding: '3px 9px' }}
                      onClick={() => run.mutate(playbook)}
                      disabled={run.isPending || !playbook.enabled}
                    >
                      ▶ Run
                    </Button>
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {shown && (
        <Card
          title={`Execution log · ${shown.id.slice(0, 8)}`}
          accent="navy"
          actions={
            <Tag
              tone={
                shown.status === 'failed'
                  ? 'red'
                  : shown.status === 'success'
                    ? 'green'
                    : shown.status === 'dry_run'
                      ? 'amber'
                      : 'navy'
              }
            >
              {shown.status.replace('_', ' ')}
            </Tag>
          }
        >
          {shown.error && <ErrorBanner error={new Error(shown.error)} />}
          <div className="timeline">
            {shown.step_results.map((step) => (
              <div className="tl-item" key={`${step.index}-${step.name}`}>
                <div
                  className="tl-dot"
                  style={{
                    background:
                      step.status === 'failed'
                        ? 'var(--red)'
                        : step.status === 'dry_run'
                          ? 'var(--amber)'
                          : 'var(--green)',
                  }}
                />
                <div className="tl-content">
                  <div className="tl-time">
                    {formatTime(step.at)} · step {step.index + 1}
                    {step.kind && ` · ${step.kind}`}
                  </div>
                  <div className="tl-text">{step.name}</div>
                  {typeof step.detail?.would_do === 'string' && step.detail.would_do && (
                    <div style={{ fontSize: 9.5, color: 'var(--tx-muted)', marginTop: 2 }}>
                      Would: {step.detail.would_do}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card title="Recent runs" bodyClassName="">
        {runs.data?.items.length === 0 && (
          <div style={{ padding: 16, textAlign: 'center', fontSize: 11, color: 'var(--tx-muted)' }}>
            No playbook runs yet.
          </div>
        )}
        {runs.data?.items.map((entry) => (
          <div
            className="exec-row"
            key={entry.id}
            onClick={() => setActiveRun(entry)}
            style={{ cursor: 'pointer' }}
          >
            <span className="exec-tool">{entry.id.slice(0, 8)}</span>
            <span style={{ flex: 1, fontSize: 10, color: 'var(--tx-muted)' }}>
              {entry.triggered_by}
            </span>
            <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              {entry.current_step}/{entry.total_steps} steps
            </span>
            {entry.dry_run && <Tag tone="amber">DRY</Tag>}
            <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              {relativeTime(entry.created_at)}
            </span>
            <Tag
              tone={
                entry.status === 'failed' ? 'red' : entry.status === 'success' ? 'green' : 'navy'
              }
            >
              {entry.status.replace('_', ' ')}
            </Tag>
          </div>
        ))}
      </Card>
    </div>
  );
}
