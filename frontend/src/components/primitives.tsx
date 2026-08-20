/** Small presentational building blocks shared by every module. */

import type { ReactNode } from 'react';
import { healthClass, riskTone, severityTone, statusTone } from '@/lib/format';
import type { HealthState, Severity } from '@/types/api';

export function Tag({
  tone = 'gray',
  children,
  title,
}: {
  tone?: string;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span className={`tag tag-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function SeverityTag({ severity }: { severity: Severity | string }) {
  return <Tag tone={severityTone(severity)}>{severity}</Tag>;
}

export function StatusTag({ status }: { status: string }) {
  return <Tag tone={statusTone(status)}>{status.replace(/_/g, ' ')}</Tag>;
}

export function RiskTag({ risk }: { risk: string }) {
  return <Tag tone={riskTone(risk)}>{risk.replace(/_/g, ' ')}</Tag>;
}

export function HealthDot({ health }: { health: HealthState | string }) {
  return <div className={`h-dot ${healthClass(health)}`} title={String(health)} />;
}

export function Card({
  title,
  accent,
  actions,
  children,
  bodyClassName = 'card-body',
}: {
  title?: ReactNode;
  accent?: 'navy' | 'gold';
  actions?: ReactNode;
  children: ReactNode;
  bodyClassName?: string;
}) {
  const accentClass = accent ? ` card-${accent}-accent` : '';
  return (
    <div className={`card${accentClass}`}>
      {title !== undefined && (
        <div className="card-head">
          <span className="card-title">{title}</span>
          {actions && (
            <span style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>{actions}</span>
          )}
        </div>
      )}
      <div className={bodyClassName}>{children}</div>
    </div>
  );
}

export function Button({
  variant = 'default',
  onClick,
  disabled,
  type = 'button',
  title,
  children,
  style,
}: {
  variant?: 'default' | 'navy' | 'gold' | 'danger';
  onClick?: () => void;
  disabled?: boolean;
  type?: 'button' | 'submit';
  title?: string;
  children: ReactNode;
  style?: React.CSSProperties;
}) {
  const variantClass = variant === 'default' ? '' : ` btn-${variant}`;
  return (
    <button
      type={type}
      className={`btn${variantClass}`}
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={style}
    >
      {children}
    </button>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="route-fallback" role="status" aria-live="polite">
      <div className="spinner" />
      {label && <div>{label}</div>}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-state-title">{title}</div>
      {hint && <div>{hint}</div>}
    </div>
  );
}

export function ErrorBanner({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const message = error instanceof Error ? error.message : 'An unexpected error occurred.';
  return (
    <div className="error-banner" role="alert">
      <span>⚠</span>
      <div style={{ flex: 1 }}>
        <strong>Request failed.</strong> {message}
      </div>
      {onRetry && (
        <Button onClick={onRetry} style={{ fontSize: 9, padding: '3px 9px' }}>
          Retry
        </Button>
      )}
    </div>
  );
}

/**
 * Renders agent/tool text that has already been escaped by `renderMarkdown`.
 *
 * Isolated into one component so the single `dangerouslySetInnerHTML` in the
 * app sits next to the sanitiser that feeds it.
 */
export function Markdown({ html }: { html: string }) {
  return <div className="md-body" dangerouslySetInnerHTML={{ __html: html }} />;
}

export function ProgressBar({ percent, tone = 'navy' }: { percent: number; tone?: string }) {
  const clamped = Math.max(0, Math.min(100, percent));
  return (
    <div
      className="run-progress"
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="run-progress-bar"
        style={{ width: `${clamped}%`, background: `var(--${tone})` }}
      />
    </div>
  );
}
