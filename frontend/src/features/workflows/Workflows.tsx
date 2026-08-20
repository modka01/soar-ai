import { useQuery } from '@tanstack/react-query';
import { workflows } from '@/api/resources';
import { Card, ErrorBanner, Spinner, Tag } from '@/components/primitives';
import { relativeTime } from '@/lib/format';
import type { Workflow } from '@/types/api';

const NODE_ICON: Record<string, string> = {
  trigger: '⚡',
  webhook: '⚡',
  ai: '✦',
  anthropic: '✦',
  if: '◆',
  switch: '◆',
};

function nodeIcon(type: string): string {
  const lower = type.toLowerCase();
  for (const [key, icon] of Object.entries(NODE_ICON)) {
    if (lower.includes(key)) return icon;
  }
  return '⚙';
}

export function Workflows() {
  const list = useQuery({ queryKey: ['workflows'], queryFn: () => workflows.list(), retry: false });
  const runs = useQuery({
    queryKey: ['workflow-runs'],
    queryFn: () => workflows.runs(30),
    refetchInterval: 30_000,
  });

  return (
    <div className="scroll-area">
      <div className="highlight-box">
        <strong>✦ n8n orchestration</strong> — workflows call the platform&apos;s AI nodes for
        analysis and decision-making. Every execution posts back to the SOAR callback endpoint, so
        the run history below reflects what actually happened in the engine.
      </div>

      {list.error && (
        <div className="highlight-box" style={{ marginBottom: 14 }}>
          <strong>n8n is not connected.</strong> Set <code>SOAR_N8N_URL</code> and{' '}
          <code>SOAR_N8N_API_KEY</code> to list workflows here. Playbooks still run in dry-run mode
          without it.
        </div>
      )}

      {list.isLoading && <Spinner label="Loading workflows…" />}

      {list.data?.map((workflow) => (
        <WorkflowCard workflow={workflow} key={workflow.id} />
      ))}

      <Card title="Execution history" bodyClassName="">
        {runs.error && <ErrorBanner error={runs.error} />}
        {runs.data?.items.length === 0 && (
          <div style={{ padding: 16, textAlign: 'center', fontSize: 11, color: 'var(--tx-muted)' }}>
            No workflow executions recorded yet.
          </div>
        )}
        {runs.data?.items.map((entry) => {
          const row = entry as unknown as {
            id: string;
            workflow_name: string;
            execution_id: string;
            status: string;
            duration_ms: number;
            created_at: string;
          };
          return (
            <div className="exec-row" key={row.id}>
              <span className="exec-tool">{row.workflow_name || row.execution_id}</span>
              <span style={{ flex: 1, fontSize: 9, color: 'var(--tx-muted)' }}>
                {row.execution_id}
              </span>
              <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
                {(row.duration_ms / 1000).toFixed(1)}s
              </span>
              <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
                {relativeTime(row.created_at)}
              </span>
              <Tag
                tone={row.status === 'success' ? 'green' : row.status === 'failed' ? 'red' : 'navy'}
              >
                {row.status}
              </Tag>
            </div>
          );
        })}
      </Card>
    </div>
  );
}

function WorkflowCard({ workflow }: { workflow: Workflow }) {
  return (
    <Card
      title={workflow.name}
      accent="navy"
      actions={
        <>
          <Tag tone={workflow.active ? 'green' : 'gray'}>
            {workflow.active ? 'ACTIVE' : 'INACTIVE'}
          </Tag>
          {workflow.updated_at && (
            <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              updated {relativeTime(workflow.updated_at)}
            </span>
          )}
        </>
      }
    >
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        {workflow.nodes.map((node, index) => (
          <div
            key={`${node.name}-${index}`}
            style={{ display: 'flex', alignItems: 'center', gap: 8 }}
          >
            <div className="wf-node">
              <div className="wf-node-icon">{nodeIcon(node.type)}</div>
              <div className="wf-node-label">{node.name}</div>
            </div>
            {index < workflow.nodes.length - 1 && (
              <span style={{ color: 'var(--br-strong)', fontSize: 14 }}>→</span>
            )}
          </div>
        ))}
        {workflow.nodes.length === 0 && (
          <span style={{ fontSize: 10.5, color: 'var(--tx-muted)' }}>
            This workflow exposes no node graph.
          </span>
        )}
      </div>
      {workflow.tags.length > 0 && (
        <div style={{ display: 'flex', gap: 5, marginTop: 10 }}>
          {workflow.tags.map((tag) => (
            <Tag tone="gray" key={tag}>
              {tag}
            </Tag>
          ))}
        </div>
      )}
    </Card>
  );
}
