/** Display helpers shared across modules. */

import type { AlertStatus, HealthState, IncidentStatus, Severity } from '@/types/api';

/** Maps a severity to the `tag-*` class the component layer defines. */
export function severityTone(severity: Severity | string): string {
  switch (severity) {
    case 'critical':
      return 'red';
    case 'high':
      return 'amber';
    case 'medium':
      return 'blue';
    case 'low':
      return 'green';
    default:
      return 'gray';
  }
}

export function statusTone(status: AlertStatus | IncidentStatus | string): string {
  switch (status) {
    case 'open':
      return 'red';
    case 'investigating':
      return 'amber';
    case 'contained':
    case 'eradicated':
      return 'navy';
    case 'automated':
      return 'cyan';
    case 'closed':
    case 'false_positive':
      return 'green';
    default:
      return 'gray';
  }
}

export function healthClass(health: HealthState | string): string {
  switch (health) {
    case 'healthy':
      return 'ok';
    case 'degraded':
      return 'warn';
    case 'offline':
      return 'err';
    default:
      return 'warn';
  }
}

export function riskTone(risk: string): string {
  switch (risk) {
    case 'critical':
      return 'red';
    case 'high':
      return 'amber';
    case 'medium':
      return 'blue';
    case 'low':
      return 'green';
    default:
      return 'gray';
  }
}

/** HH:MM:SS in the viewer's locale — matches the console's dense table style. */
export function formatTime(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('en-GB', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** "4 min ago" — the SOC cares about recency far more than wall-clock time. */
export function relativeTime(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';

  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 0) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDateTime(value);
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

export function formatNumber(value: number): string {
  if (Math.abs(value) >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (Math.abs(value) >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return String(value);
}

export function truncate(text: string, max = 120): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/**
 * Render the small Markdown subset the agent emits.
 *
 * Input is escaped first, so agent or tool output can never inject markup —
 * this text comes from a model and from third-party APIs.
 */
export function renderMarkdown(text: string): string {
  const escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  return escaped
    .replace(/^### (.*)$/gm, '<h4 class="md-h4">$1</h4>')
    .replace(/^## (.*)$/gm, '<h3 class="md-h3">$1</h3>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+?)`/g, '<code class="md-code">$1</code>')
    .replace(
      /^- (.*)$/gm,
      '<div class="md-li"><span class="md-bullet">•</span><span>$1</span></div>',
    )
    .replace(
      /^(\d+)\. (.*)$/gm,
      '<div class="md-li"><span class="md-num">$1.</span><span>$2</span></div>',
    )
    .replace(/\n/g, '<br />');
}
