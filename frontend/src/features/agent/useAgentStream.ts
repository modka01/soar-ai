/**
 * Drives one agent session and reduces its SSE feed into render-ready state.
 *
 * The reducer is the single place that knows how a stream event changes the
 * console, which keeps the view component free of transport concerns and makes
 * the behaviour testable without a network.
 */

import { useCallback, useReducer, useRef } from 'react';
import { agent } from '@/api/resources';
import type { AgentStreamEvent, ProposedAction, RetrievalHit } from '@/types/api';

export interface TranscriptEntry {
  id: string;
  kind: 'user' | 'assistant' | 'thought' | 'system' | 'error' | 'tool' | 'final';
  text?: string;
  at: string;
  citations?: RetrievalHit[];
  tool?: {
    name: string;
    ok: boolean;
    reason?: string;
    params?: Record<string, unknown>;
    result: Record<string, unknown>;
    durationMs: number;
    dryRun: boolean;
  };
}

export interface PendingApproval {
  approvalId: string;
  reason: string;
  actions: ProposedAction[];
  expiresAt: string;
}

export interface AgentState {
  sessionId: string | null;
  status: 'idle' | 'thinking' | 'executing' | 'awaiting_approval' | 'done' | 'error' | 'stopped';
  transcript: TranscriptEntry[];
  plan: string[];
  planCursor: number;
  context: RetrievalHit[];
  toolLog: TranscriptEntry[];
  approval: PendingApproval | null;
  iteration: number;
  tokens: { input: number; output: number };
  error: string | null;
}

const INITIAL: AgentState = {
  sessionId: null,
  status: 'idle',
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

type Action =
  | { type: 'reset' }
  | { type: 'start'; sessionId: string; task: string }
  | { type: 'event'; event: AgentStreamEvent }
  | { type: 'resolveApproval' }
  | { type: 'fail'; message: string };

let entrySeq = 0;
const nextId = () => `entry-${++entrySeq}`;
const stamp = () => new Date().toISOString();

export function agentReducer(state: AgentState, action: Action): AgentState {
  switch (action.type) {
    case 'reset':
      return { ...INITIAL };

    case 'start':
      return {
        ...INITIAL,
        sessionId: action.sessionId,
        status: 'thinking',
        transcript: [{ id: nextId(), kind: 'user', text: action.task, at: stamp() }],
      };

    case 'fail':
      return {
        ...state,
        status: 'error',
        error: action.message,
        transcript: [
          ...state.transcript,
          { id: nextId(), kind: 'error', text: action.message, at: stamp() },
        ],
      };

    case 'resolveApproval':
      return { ...state, approval: null, status: 'thinking' };

    case 'event':
      return applyEvent(state, action.event);

    default:
      return state;
  }
}

function applyEvent(state: AgentState, event: AgentStreamEvent): AgentState {
  switch (event.type) {
    case 'context':
      return { ...state, context: event.chunks };

    case 'iteration':
      return { ...state, iteration: event.iteration, status: 'thinking' };

    case 'plan':
      return { ...state, plan: event.steps, planCursor: event.cursor };

    case 'thought':
      return {
        ...state,
        transcript: [
          ...state.transcript,
          { id: nextId(), kind: 'thought', text: event.text, at: stamp() },
        ],
      };

    case 'message':
      return {
        ...state,
        transcript: [
          ...state.transcript,
          {
            id: nextId(),
            kind: 'assistant',
            text: event.text,
            at: stamp(),
            citations: state.context,
          },
        ],
      };

    case 'tool_result': {
      const entry: TranscriptEntry = {
        id: nextId(),
        kind: 'tool',
        at: stamp(),
        tool: {
          name: event.tool,
          ok: event.ok,
          reason: event.reason,
          params: event.params,
          result: event.result,
          durationMs: event.duration_ms,
          dryRun: Boolean(event.dry_run),
        },
      };
      return {
        ...state,
        status: 'executing',
        transcript: [...state.transcript, entry],
        // Newest first: the side panel is read top-down for "what just happened".
        toolLog: [entry, ...state.toolLog].slice(0, 60),
      };
    }

    case 'approval_required':
      return {
        ...state,
        status: 'awaiting_approval',
        approval: {
          approvalId: event.approval_id,
          reason: event.reason,
          actions: event.actions,
          expiresAt: event.expires_at,
        },
      };

    case 'approval_decided':
      return { ...state, approval: null, status: 'thinking' };

    case 'final':
      return {
        ...state,
        status: 'done',
        planCursor: state.plan.length,
        tokens: event.tokens ?? state.tokens,
        transcript: [
          ...state.transcript,
          {
            id: nextId(),
            kind: 'final',
            text: event.answer,
            at: stamp(),
            citations: state.context,
          },
        ],
      };

    case 'exhausted':
      return {
        ...state,
        status: 'done',
        transcript: [
          ...state.transcript,
          {
            id: nextId(),
            kind: 'system',
            text: `Stopped after ${event.iterations} iterations without a conclusion.`,
            at: stamp(),
          },
        ],
      };

    case 'stopped':
      return {
        ...state,
        status: 'stopped',
        transcript: [
          ...state.transcript,
          { id: nextId(), kind: 'system', text: `Agent stopped by ${event.by}.`, at: stamp() },
        ],
      };

    case 'error':
      return {
        ...state,
        status: 'error',
        error: event.message,
        transcript: [
          ...state.transcript,
          { id: nextId(), kind: 'error', text: event.message, at: stamp() },
        ],
      };

    default:
      return state;
  }
}

export function useAgentStream() {
  const [state, dispatch] = useReducer(agentReducer, INITIAL);
  const abortRef = useRef<AbortController | null>(null);

  const submit = useCallback(async (task: string, incidentId?: string) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    let sessionId: string;
    try {
      const session = await agent.createTask(task, incidentId);
      sessionId = session.id;
      dispatch({ type: 'start', sessionId, task });
    } catch (error) {
      dispatch({
        type: 'fail',
        message: error instanceof Error ? error.message : 'Could not start the agent.',
      });
      return;
    }

    try {
      for await (const frame of agent.stream(sessionId, controller.signal)) {
        if (frame.event === 'done') break;
        dispatch({
          type: 'event',
          event: { type: frame.event, ...(frame.data as object) } as AgentStreamEvent,
        });
      }
    } catch (error) {
      // An aborted stream is a deliberate stop, not a failure to report.
      if (controller.signal.aborted) return;
      dispatch({
        type: 'fail',
        message: error instanceof Error ? error.message : 'The agent stream failed.',
      });
    }
  }, []);

  const stop = useCallback(async () => {
    abortRef.current?.abort();
    if (state.sessionId) {
      try {
        await agent.stop(state.sessionId);
      } catch {
        // The session may already be terminal; the UI state below is authoritative.
      }
    }
    dispatch({
      type: 'event',
      event: { type: 'stopped', session_id: '', status: 'stopped', by: 'you' },
    });
  }, [state.sessionId]);

  const decide = useCallback(
    async (approved: boolean, note?: string) => {
      if (!state.approval) return;
      const { approvalId } = state.approval;
      dispatch({ type: 'resolveApproval' });
      await agent.decide(approvalId, approved, note);

      // Deciding resumes the loop server-side; re-attach to the same feed.
      if (state.sessionId && approved) {
        const controller = new AbortController();
        abortRef.current = controller;
        try {
          for await (const frame of agent.stream(state.sessionId, controller.signal, true)) {
            if (frame.event === 'done') break;
            dispatch({
              type: 'event',
              event: { type: frame.event, ...(frame.data as object) } as AgentStreamEvent,
            });
          }
        } catch {
          // Following is best-effort; the transcript can be reloaded from the API.
        }
      }
    },
    [state.approval, state.sessionId],
  );

  const reset = useCallback(() => {
    abortRef.current?.abort();
    dispatch({ type: 'reset' });
  }, []);

  return { state, submit, stop, decide, reset };
}
