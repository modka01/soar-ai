import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { mcp } from '@/api/resources';
import { Button, RiskTag, Tag } from '@/components/primitives';
import { formatDuration, formatTime, renderMarkdown, truncate } from '@/lib/format';
import { useAgentStream, type TranscriptEntry } from './useAgentStream';
import type { RetrievalHit } from '@/types/api';

const QUICK_TASKS = [
  {
    label: '🔍 Investigate criticals',
    task: 'Investigate all critical alerts, enrich the IOCs, and recommend containment.',
  },
  {
    label: '⚡ Auto-triage',
    task: 'Run a full security triage on the incident queue and prioritise by risk.',
  },
  {
    label: '☁ AWS audit',
    task: 'Check AWS GuardDuty findings and report the top remediation actions.',
  },
  {
    label: 'Σ Generate rules',
    task: 'Generate Sigma rules for the open incidents based on the TTPs observed.',
  },
  {
    label: '📊 SIEM query',
    task: 'Query the SIEM for lateral movement indicators in the last 24 hours.',
  },
];

const STATE_LABEL: Record<string, { text: string; cls: string; dot: string }> = {
  idle: { text: 'READY', cls: 'state-ready', dot: 'var(--green)' },
  thinking: { text: 'THINKING', cls: 'state-thinking', dot: 'var(--gold)' },
  executing: { text: 'EXECUTING', cls: 'state-exec', dot: 'var(--blue)' },
  awaiting_approval: { text: 'AWAITING APPROVAL', cls: 'state-approval', dot: 'var(--amber)' },
  done: { text: 'READY', cls: 'state-ready', dot: 'var(--green)' },
  stopped: { text: 'STOPPED', cls: 'state-stopped', dot: 'var(--red)' },
  error: { text: 'ERROR', cls: 'state-stopped', dot: 'var(--red)' },
};

type SidePanel = 'tools' | 'context' | 'plan' | 'log';

export function AgentConsole() {
  const { state, submit, stop, decide, reset } = useAgentStream();
  const [input, setInput] = useState('');
  const [panel, setPanel] = useState<SidePanel>('tools');
  const messagesRef = useRef<HTMLDivElement>(null);

  const { data: tools } = useQuery({ queryKey: ['mcp', 'tools'], queryFn: mcp.listTools });

  useEffect(() => {
    messagesRef.current?.scrollTo({ top: messagesRef.current.scrollHeight, behavior: 'smooth' });
  }, [state.transcript.length, state.approval]);

  const running = state.status === 'thinking' || state.status === 'executing';
  const badge = STATE_LABEL[state.status] ?? STATE_LABEL.idle!;

  const send = (task: string) => {
    const trimmed = task.trim();
    if (!trimmed || running) return;
    setInput('');
    void submit(trimmed);
  };

  return (
    <div className="agent-shell">
      <div className="agent-main">
        <div className="agent-topbar">
          <div
            className={`agent-dot${running ? ' thinking' : ''}`}
            style={{ background: badge.dot }}
          />
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--navy)' }}>
              QuantNexa Security Agent
            </div>
            <div style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              Agentic loop · RAG-augmented · {tools?.length ?? 0} MCP tools
              {state.iteration > 0 && ` · iteration ${state.iteration}`}
            </div>
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
            {state.tokens.input > 0 && (
              <span
                style={{ fontSize: 9, color: 'var(--tx-muted)', fontFamily: 'var(--font-mono)' }}
              >
                {state.tokens.input}in / {state.tokens.output}out
              </span>
            )}
            <span className={`agent-state-badge ${badge.cls}`}>{badge.text}</span>
            {running && (
              <Button variant="danger" onClick={() => void stop()}>
                ■ Stop
              </Button>
            )}
            {!running && state.transcript.length > 0 && <Button onClick={reset}>Clear</Button>}
          </div>
        </div>

        <div className="agent-messages" ref={messagesRef}>
          {state.transcript.length === 0 && (
            <div className="empty-state">
              <div className="empty-state-title">No active task</div>
              <div>Assign the agent a security task, or pick one of the presets below.</div>
            </div>
          )}
          {state.transcript.map((entry) => (
            <Entry key={entry.id} entry={entry} />
          ))}
          {running && <Thinking />}
          {state.approval && (
            <ApprovalGate
              reason={state.approval.reason}
              actions={state.approval.actions}
              onDecide={(approved) => void decide(approved)}
            />
          )}
        </div>

        <div className="agent-input-bar">
          <div className="input-chips">
            {QUICK_TASKS.map((quick) => (
              <span key={quick.label} className="input-chip" onClick={() => send(quick.task)}>
                {quick.label}
              </span>
            ))}
          </div>
          <div className="input-row">
            <textarea
              className="agent-input"
              rows={2}
              value={input}
              disabled={running}
              placeholder="Assign a security task to the agent… (Enter to send, Shift+Enter for a newline)"
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault();
                  send(input);
                }
              }}
              aria-label="Agent task"
            />
            <button
              className="send-btn"
              onClick={() => send(input)}
              disabled={running || !input.trim()}
              aria-label="Send task"
            >
              <svg fill="none" viewBox="0 0 16 16" strokeWidth={2} stroke="currentColor">
                <path d="M2 8h12M9 3l5 5-5 5" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      <div className="agent-side">
        <div className="atabs">
          {(['tools', 'context', 'plan', 'log'] as SidePanel[]).map((key) => (
            <div
              key={key}
              className={`atab${panel === key ? ' active' : ''}`}
              onClick={() => setPanel(key)}
            >
              {key[0]!.toUpperCase() + key.slice(1)}
            </div>
          ))}
        </div>

        <div className="atab-panel active">
          {panel === 'tools' && <ToolsPanel tools={tools ?? []} />}
          {panel === 'context' && <ContextPanel chunks={state.context} />}
          {panel === 'plan' && <PlanPanel steps={state.plan} cursor={state.planCursor} />}
          {panel === 'log' && <LogPanel entries={state.toolLog} />}
        </div>
      </div>
    </div>
  );
}

function Entry({ entry }: { entry: TranscriptEntry }) {
  if (entry.kind === 'thought') {
    return (
      <div className="think-block fade-in">
        <div className="think-label">Reasoning</div>
        {entry.text}
      </div>
    );
  }

  if (entry.kind === 'tool' && entry.tool) {
    const { tool } = entry;
    return (
      <div className="tool-call fade-in">
        <div className="tool-call-head">
          <Tag tone="navy">MCP</Tag>
          <span className="tool-name">{tool.name}()</span>
          {tool.reason && (
            <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              {truncate(tool.reason, 60)}
            </span>
          )}
          <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
            {tool.dryRun && <Tag tone="amber">DRY RUN</Tag>}
            <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              {formatDuration(tool.durationMs)}
            </span>
            <Tag tone={tool.ok ? 'green' : 'red'}>{tool.ok ? '✓ OK' : 'ERR'}</Tag>
          </span>
        </div>
        {tool.params && Object.keys(tool.params).length > 0 && (
          <div style={{ fontSize: 9, color: 'var(--tx-muted)', marginBottom: 3 }}>
            params:{' '}
            <code style={{ color: 'var(--navy)' }}>
              {truncate(JSON.stringify(tool.params), 140)}
            </code>
          </div>
        )}
        <div className={`tool-result${tool.ok ? '' : ' error'}`}>
          {truncate(JSON.stringify(tool.result, null, 2), 700)}
        </div>
      </div>
    );
  }

  const ROLE = {
    user: { label: 'You', colour: 'var(--navy)', bubble: 'user' },
    assistant: { label: 'Agent', colour: 'var(--green)', bubble: 'assistant' },
    final: { label: 'Agent', colour: 'var(--green)', bubble: 'assistant' },
    system: { label: 'System', colour: 'var(--gold-deep)', bubble: 'system' },
    error: { label: 'Error', colour: 'var(--red)', bubble: 'error' },
    thought: { label: 'Agent', colour: 'var(--gold-deep)', bubble: 'system' },
    tool: { label: 'Tool', colour: 'var(--navy)', bubble: 'system' },
  }[entry.kind];

  return (
    <div className="msg fade-in">
      <div className="msg-meta">
        <span className="msg-role" style={{ color: ROLE.colour }}>
          {ROLE.label}
        </span>
        <span>{formatTime(entry.at)}</span>
        {entry.kind === 'final' && <Tag tone="green">COMPLETE</Tag>}
      </div>
      <div
        className={`msg-bubble ${ROLE.bubble}`}
        dangerouslySetInnerHTML={{ __html: renderMarkdown(entry.text ?? '') }}
      />
      {entry.citations && entry.citations.length > 0 && (
        <div className="rag-chips">
          {entry.citations.map((chunk) => (
            <span className="rag-chip" key={chunk.chunk_id} title={chunk.title}>
              {chunk.source}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function Thinking() {
  return (
    <div className="msg fade-in">
      <div className="msg-meta">
        <span className="msg-role" style={{ color: 'var(--gold-deep)' }}>
          Agent
        </span>
        <span>thinking…</span>
      </div>
      <div className="msg-bubble system">
        <span className="thinking-dots">
          <span />
          <span />
          <span />
        </span>
      </div>
    </div>
  );
}

function ApprovalGate({
  reason,
  actions,
  onDecide,
}: {
  reason: string;
  actions: { tool: string; params: Record<string, unknown>; risk: string }[];
  onDecide: (approved: boolean) => void;
}) {
  return (
    <div className="approval-gate fade-in" role="alertdialog" aria-label="Approval required">
      <div className="approval-title">⚠ Human approval required</div>
      <div className="approval-detail">
        <strong>Reason:</strong> {reason}
        <br />
        <br />
        <strong>Proposed actions:</strong>
        <br />
        {actions.map((action, index) => (
          <div key={`${action.tool}-${index}`} style={{ marginTop: 4 }}>
            • <code style={{ color: 'var(--navy)' }}>{action.tool}</code>{' '}
            <RiskTag risk={action.risk} />
            <div style={{ fontSize: 9, color: 'var(--tx-muted)', marginLeft: 12 }}>
              {truncate(JSON.stringify(action.params), 120)}
            </div>
          </div>
        ))}
      </div>
      <div className="approval-actions">
        <Button variant="navy" onClick={() => onDecide(true)}>
          ✓ Approve
        </Button>
        <Button variant="danger" onClick={() => onDecide(false)}>
          ✗ Reject
        </Button>
      </div>
    </div>
  );
}

function PanelLabel({ children }: { children: string }) {
  return (
    <div
      style={{
        fontSize: 8,
        color: 'var(--tx-muted)',
        textTransform: 'uppercase',
        letterSpacing: '1.2px',
        marginBottom: 8,
        fontFamily: 'var(--font-mono)',
      }}
    >
      {children}
    </div>
  );
}

function ToolsPanel({
  tools,
}: {
  tools: { name: string; label: string; icon: string; risk: string; calls: number }[];
}) {
  return (
    <>
      <PanelLabel>MCP tools available</PanelLabel>
      {tools.map((tool) => (
        <div className="tool-item" key={tool.name}>
          <span style={{ fontSize: 13 }}>{tool.icon}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="tool-item-name">{tool.name}</div>
            <div style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              {tool.calls} call{tool.calls === 1 ? '' : 's'}
            </div>
          </div>
          <RiskTag risk={tool.risk} />
        </div>
      ))}
    </>
  );
}

function ContextPanel({ chunks }: { chunks: RetrievalHit[] }) {
  return (
    <>
      <PanelLabel>Retrieved RAG context</PanelLabel>
      {chunks.length === 0 ? (
        <div
          style={{
            fontSize: 10.5,
            color: 'var(--tx-muted)',
            textAlign: 'center',
            padding: '24px 10px',
          }}
        >
          No context retrieved yet.
          <br />
          Assign a task to trigger retrieval.
        </div>
      ) : (
        chunks.map((chunk) => (
          <div className="rag-context-item" key={chunk.chunk_id}>
            <div className="rag-context-head">
              <span className="rag-source">{chunk.source}</span>
              <span className="rag-score">{(chunk.score * 100).toFixed(0)}%</span>
            </div>
            <div className="rag-context-title">{chunk.title}</div>
            <div className="rag-context-text">{truncate(chunk.text, 220)}</div>
          </div>
        ))
      )}
    </>
  );
}

function PlanPanel({ steps, cursor }: { steps: string[]; cursor: number }) {
  return (
    <>
      <PanelLabel>Agent execution plan</PanelLabel>
      {steps.length === 0 ? (
        <div
          style={{
            fontSize: 10.5,
            color: 'var(--tx-muted)',
            textAlign: 'center',
            padding: '24px 10px',
          }}
        >
          No active plan.
          <br />
          Assign a task to see the agent&apos;s reasoning steps.
        </div>
      ) : (
        steps.map((step, index) => {
          const done = index < cursor;
          const current = index === cursor;
          return (
            <div className="plan-step" key={`${index}-${step}`}>
              <div className={`plan-num ${done ? 'done' : current ? 'current' : 'pending'}`}>
                {done ? '✓' : index + 1}
              </div>
              <div
                style={{
                  color: current ? 'var(--tx-primary)' : 'var(--tx-muted)',
                  lineHeight: 1.5,
                }}
              >
                {step}
              </div>
            </div>
          );
        })
      )}
    </>
  );
}

function LogPanel({ entries }: { entries: TranscriptEntry[] }) {
  return (
    <>
      <PanelLabel>Tool execution log</PanelLabel>
      {entries.length === 0 ? (
        <div
          style={{
            fontSize: 10.5,
            color: 'var(--tx-muted)',
            textAlign: 'center',
            padding: '24px 10px',
          }}
        >
          No executions yet.
        </div>
      ) : (
        entries.map((entry) => (
          <div className="exec-row" key={entry.id}>
            <span className="exec-tool">{entry.tool?.name}</span>
            <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--tx-muted)' }}>
              {formatDuration(entry.tool?.durationMs ?? 0)}
            </span>
            <Tag tone={entry.tool?.ok ? 'green' : 'red'}>{entry.tool?.ok ? 'OK' : 'ERR'}</Tag>
          </div>
        ))
      )}
    </>
  );
}
