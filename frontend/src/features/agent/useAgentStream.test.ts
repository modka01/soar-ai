/**
 * The reducer is the agent console's core logic — it decides what the operator
 * sees for every stream event, including the approval gate. Tested directly so
 * the behaviour is pinned without a network or a rendered tree.
 */

import { describe, expect, it } from 'vitest';
import { agentReducer, type AgentState } from './useAgentStream';
import type { AgentStreamEvent } from '@/types/api';

const BASE: AgentState = {
  sessionId: 'session-1',
  status: 'thinking',
  transcript: [],
  plan: [],
  planCursor: 0,
  context: [],
  toolLog: [],
  approval: null,
  iteration: 0,
  tokens: { input: 0, output: 0 },
  error: null,
};

const apply = (state: AgentState, event: AgentStreamEvent) =>
  agentReducer(state, { type: 'event', event });

describe('agentReducer', () => {
  it('seeds the transcript with the operator task', () => {
    const state = agentReducer(BASE, {
      type: 'start',
      sessionId: 'session-2',
      task: 'Investigate INC-047',
    });
    expect(state.status).toBe('thinking');
    expect(state.transcript).toHaveLength(1);
    expect(state.transcript[0]).toMatchObject({ kind: 'user', text: 'Investigate INC-047' });
  });

  it('stores retrieved context and attaches it as citations on the next message', () => {
    let state = apply(BASE, {
      type: 'context',
      session_id: 's',
      status: 'thinking',
      chunks: [
        {
          chunk_id: 'c1',
          title: 'T1021.002',
          source: 'MITRE ATT&CK',
          category: 'Lateral Movement',
          text: '…',
          score: 0.82,
        },
      ],
    });
    state = apply(state, {
      type: 'message',
      session_id: 's',
      status: 'thinking',
      text: 'Querying the SIEM.',
    });

    expect(state.context).toHaveLength(1);
    expect(state.transcript.at(-1)?.citations?.[0]?.source).toBe('MITRE ATT&CK');
  });

  it('tracks plan progress', () => {
    const state = apply(BASE, {
      type: 'plan',
      session_id: 's',
      status: 'thinking',
      steps: ['Query SIEM', 'Enrich IOCs', 'Contain'],
      cursor: 2,
    });
    expect(state.plan).toHaveLength(3);
    expect(state.planCursor).toBe(2);
  });

  it('records a tool result in both the transcript and the newest-first log', () => {
    const state = apply(BASE, {
      type: 'tool_result',
      session_id: 's',
      status: 'executing',
      tool: 'enrich_ioc',
      ok: true,
      result: { verdict: 'malicious' },
      duration_ms: 340,
      dry_run: false,
    });

    expect(state.status).toBe('executing');
    expect(state.transcript.at(-1)?.tool).toMatchObject({ name: 'enrich_ioc', ok: true });
    expect(state.toolLog[0]?.tool?.name).toBe('enrich_ioc');
  });

  it('surfaces a dry run so the operator is never misled about what happened', () => {
    const state = apply(BASE, {
      type: 'tool_result',
      session_id: 's',
      status: 'executing',
      tool: 'block_ip',
      ok: true,
      result: { would_block: '185.220.101.47/32', dry_run: true },
      duration_ms: 12,
      dry_run: true,
    });
    expect(state.transcript.at(-1)?.tool?.dryRun).toBe(true);
  });

  it('parks on an approval gate and exposes the proposed actions', () => {
    const state = apply(BASE, {
      type: 'approval_required',
      session_id: 's',
      status: 'awaiting_approval',
      approval_id: 'apr-1',
      reason: 'Isolation cuts the host off the network.',
      actions: [
        {
          tool: 'isolate_host',
          params: { hostname: 'ws-finance-04' },
          reason: 'contain',
          risk: 'critical',
        },
      ],
      expires_at: '2026-01-01T00:00:00Z',
    });

    expect(state.status).toBe('awaiting_approval');
    expect(state.approval?.approvalId).toBe('apr-1');
    expect(state.approval?.actions[0]?.risk).toBe('critical');
  });

  it('clears the gate once a decision is recorded', () => {
    let state = apply(BASE, {
      type: 'approval_required',
      session_id: 's',
      status: 'awaiting_approval',
      approval_id: 'apr-1',
      reason: 'r',
      actions: [],
      expires_at: '2026-01-01T00:00:00Z',
    });
    state = apply(state, {
      type: 'approval_decided',
      approval_id: 'apr-1',
      approved: true,
      by: 'ir-manager',
    });

    expect(state.approval).toBeNull();
    expect(state.status).toBe('thinking');
  });

  it('completes the plan and records token usage on the final answer', () => {
    let state = apply(BASE, {
      type: 'plan',
      session_id: 's',
      status: 'thinking',
      steps: ['a', 'b'],
      cursor: 1,
    });
    state = apply(state, {
      type: 'final',
      session_id: 's',
      status: 'completed',
      answer: '## Investigation complete',
      iterations: 4,
      tokens: { input: 3200, output: 900 },
    });

    expect(state.status).toBe('done');
    expect(state.planCursor).toBe(2);
    expect(state.tokens).toEqual({ input: 3200, output: 900 });
    expect(state.transcript.at(-1)?.kind).toBe('final');
  });

  it('reports a stream error without discarding the transcript so far', () => {
    let state = apply(BASE, {
      type: 'message',
      session_id: 's',
      status: 'thinking',
      text: 'Working…',
    });
    state = apply(state, { type: 'error', message: 'Anthropic API is unreachable' });

    expect(state.status).toBe('error');
    expect(state.error).toContain('unreachable');
    expect(state.transcript).toHaveLength(2);
  });

  it('marks an iteration-limited run as finished rather than leaving it spinning', () => {
    const state = apply(BASE, {
      type: 'exhausted',
      session_id: 's',
      status: 'completed',
      iterations: 6,
    });
    expect(state.status).toBe('done');
    expect(state.transcript.at(-1)?.text).toContain('6 iterations');
  });

  it('resets to a clean slate', () => {
    const dirty = apply(BASE, {
      type: 'message',
      session_id: 's',
      status: 'thinking',
      text: 'x',
    });
    const state = agentReducer(dirty, { type: 'reset' });
    expect(state.transcript).toHaveLength(0);
    expect(state.status).toBe('idle');
  });
});
