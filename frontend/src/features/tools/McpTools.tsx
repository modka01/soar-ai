import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { mcp } from '@/api/resources';
import { Button, Card, ErrorBanner, RiskTag, Spinner, Tag } from '@/components/primitives';
import { Modal } from '@/components/Modal';
import { formatDuration, relativeTime, truncate } from '@/lib/format';
import { toastError, useToasts } from '@/lib/store';
import type { ToolSchema } from '@/types/api';

export function McpTools() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);
  const [invoking, setInvoking] = useState<ToolSchema | null>(null);
  const [params, setParams] = useState<Record<string, string>>({});

  const tools = useQuery({ queryKey: ['mcp', 'tools'], queryFn: mcp.listTools });
  const executions = useQuery({
    queryKey: ['mcp', 'executions'],
    queryFn: () => mcp.executions(40),
    refetchInterval: 20_000,
  });

  const invoke = useMutation({
    mutationFn: () => {
      if (!invoking) throw new Error('No tool selected.');
      // A destructive tool invoked from this screen always runs as a dry run;
      // real containment must go through the agent's approval gate.
      return mcp.invoke(invoking.name, coerce(params, invoking), invoking.requires_approval);
    },
    onSuccess: (execution) => {
      push(
        execution.dry_run
          ? `${execution.tool_name} completed as a dry run.`
          : `${execution.tool_name} completed in ${formatDuration(execution.duration_ms)}.`,
        execution.status === 'failed' ? 'warning' : 'success',
      );
      setInvoking(null);
      setParams({});
      void queryClient.invalidateQueries({ queryKey: ['mcp'] });
    },
    onError: (error) => toastError(error, 'Tool invocation failed.'),
  });

  return (
    <div className="scroll-area">
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="h-dot ok" />
          <span style={{ fontSize: 11, fontWeight: 600 }}>MCP tool registry</span>
          <Tag tone="green">{tools.data?.length ?? 0} REGISTERED</Tag>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <Button onClick={() => void queryClient.invalidateQueries({ queryKey: ['mcp'] })}>
            ↻ Refresh
          </Button>
        </div>
      </div>

      {tools.error && <ErrorBanner error={tools.error} onRetry={() => void tools.refetch()} />}
      {tools.isLoading ? (
        <Spinner label="Loading the tool registry…" />
      ) : (
        <div className="mcp-grid">
          {tools.data?.map((tool) => (
            <div className="mcp-card" key={tool.name}>
              <div className="mcp-head">
                <span style={{ fontSize: 17 }}>{tool.icon}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="mcp-name">{tool.name}</div>
                  <div style={{ fontSize: 9, color: 'var(--tx-muted)' }}>{tool.category}</div>
                </div>
                <RiskTag risk={tool.risk} />
              </div>
              <div className="mcp-desc">{tool.description}</div>
              <div className="mcp-meta">
                <span>{tool.calls} calls</span>
                {tool.calls > 0 && (
                  <span
                    style={{ color: tool.success_rate >= 95 ? 'var(--green)' : 'var(--amber)' }}
                  >
                    {tool.success_rate}% ok
                  </span>
                )}
                {tool.last_used_at && <span>{relativeTime(tool.last_used_at)}</span>}
                {tool.requires_approval && <Tag tone="amber">GATED</Tag>}
              </div>
              <div style={{ display: 'flex', gap: 5, marginTop: 8 }}>
                <Button
                  onClick={() => {
                    setInvoking(tool);
                    setParams({});
                  }}
                  style={{ flex: 1, fontSize: 9 }}
                >
                  {tool.requires_approval ? 'Dry run' : 'Invoke'}
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Card
        title="Execution history"
        bodyClassName=""
        actions={
          <span style={{ fontSize: 9, color: 'var(--tx-muted)', fontFamily: 'var(--font-mono)' }}>
            {executions.data?.total ?? 0} calls
          </span>
        }
      >
        <div style={{ maxHeight: 320, overflowY: 'auto' }}>
          {executions.data?.items.length === 0 && (
            <div
              style={{ padding: 16, textAlign: 'center', fontSize: 11, color: 'var(--tx-muted)' }}
            >
              No executions recorded yet.
            </div>
          )}
          {executions.data?.items.map((execution) => (
            <div className="exec-row" key={execution.id}>
              <span className="exec-tool">{execution.tool_name}</span>
              <span style={{ fontSize: 9, color: 'var(--tx-muted)', flex: 1 }}>
                {truncate(execution.invoked_by, 28)}
              </span>
              {execution.dry_run && <Tag tone="amber">DRY</Tag>}
              <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
                {formatDuration(execution.duration_ms)}
              </span>
              <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
                {relativeTime(execution.created_at)}
              </span>
              <Tag
                tone={
                  execution.status === 'failed'
                    ? 'red'
                    : execution.status === 'dry_run'
                      ? 'amber'
                      : 'green'
                }
              >
                {execution.status}
              </Tag>
            </div>
          ))}
        </div>
      </Card>

      <Modal
        open={invoking !== null}
        title={invoking ? `Invoke ${invoking.name}` : ''}
        onClose={() => setInvoking(null)}
        onConfirm={() => invoke.mutate()}
        confirmLabel={invoking?.requires_approval ? 'Run dry' : 'Invoke'}
        confirmVariant={invoking?.requires_approval ? 'gold' : 'navy'}
        busy={invoke.isPending}
      >
        {invoking && (
          <>
            <p
              style={{
                fontSize: 11,
                color: 'var(--tx-secondary)',
                lineHeight: 1.7,
                marginBottom: 12,
              }}
            >
              {invoking.description}
            </p>
            {invoking.requires_approval && (
              <div className="highlight-box" style={{ marginBottom: 12 }}>
                <strong>⚠ {invoking.risk.replace('_', ' ')} risk.</strong> This tool runs as a dry
                run here. To execute it for real, task the agent — containment passes through a
                human approval gate and is fully audited.
              </div>
            )}
            {Object.entries(invoking.schema.properties).map(([name, spec]) => (
              <div className="s-field" key={name}>
                <label className="s-label" htmlFor={`param-${name}`}>
                  {name}
                  {invoking.schema.required.includes(name) && (
                    <span style={{ color: 'var(--red)' }}> *</span>
                  )}
                </label>
                {spec.enum ? (
                  <select
                    id={`param-${name}`}
                    className="s-input-wide"
                    value={params[name] ?? ''}
                    onChange={(event) => setParams({ ...params, [name]: event.target.value })}
                  >
                    <option value="">—</option>
                    {spec.enum.map((option) => (
                      <option key={option}>{option}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    id={`param-${name}`}
                    className="s-input-wide"
                    value={params[name] ?? ''}
                    placeholder={spec.description ?? spec.type}
                    onChange={(event) => setParams({ ...params, [name]: event.target.value })}
                  />
                )}
                {spec.description && (
                  <div style={{ fontSize: 9, color: 'var(--tx-muted)', marginTop: 3 }}>
                    {spec.description}
                  </div>
                )}
              </div>
            ))}
          </>
        )}
      </Modal>
    </div>
  );
}

/** Cast form strings back to the JSON types the tool schema declares. */
function coerce(values: Record<string, string>, tool: ToolSchema): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, raw] of Object.entries(values)) {
    if (raw === '') continue;
    const type = tool.schema.properties[key]?.type;
    if (type === 'number' || type === 'integer') {
      const parsed = Number(raw);
      out[key] = Number.isNaN(parsed) ? raw : parsed;
    } else if (type === 'boolean') {
      out[key] = raw === 'true';
    } else if (type === 'object') {
      try {
        out[key] = JSON.parse(raw);
      } catch {
        out[key] = raw;
      }
    } else {
      out[key] = raw;
    }
  }
  return out;
}
