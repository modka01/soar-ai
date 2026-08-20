import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { dashboard } from '@/api/resources';
import {
  Card,
  ErrorBanner,
  HealthDot,
  SeverityTag,
  Spinner,
  StatusTag,
} from '@/components/primitives';
import { formatNumber, relativeTime } from '@/lib/format';
import type { DashboardMetrics, Severity } from '@/types/api';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
const SEVERITY_COLOUR: Record<string, string> = {
  critical: 'var(--red)',
  high: 'var(--amber)',
  medium: 'var(--navy)',
  low: 'var(--green)',
  info: 'var(--tx-muted)',
};

export function Dashboard() {
  const navigate = useNavigate();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard', 'metrics'],
    queryFn: () => dashboard.metrics(24),
    refetchInterval: 30_000,
  });

  if (isLoading) return <Spinner label="Loading operational metrics…" />;
  if (error)
    return (
      <div className="scroll-area">
        <ErrorBanner error={error} onRetry={() => void refetch()} />
      </div>
    );
  if (!data) return null;

  return (
    <div className="scroll-area">
      <MetricTiles metrics={data} onNavigate={navigate} />

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 16 }}>
        <Card
          title="Recent alerts"
          accent="navy"
          bodyClassName=""
          actions={
            <button
              className="btn"
              style={{ padding: '3px 9px', fontSize: 9 }}
              onClick={() => navigate('/alerts')}
            >
              View all →
            </button>
          }
        >
          <table className="tbl" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert</th>
                <th>Source</th>
                <th>Asset</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Seen</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_alerts.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    style={{ textAlign: 'center', color: 'var(--tx-muted)', padding: 20 }}
                  >
                    No alerts ingested yet.
                  </td>
                </tr>
              )}
              {data.recent_alerts.map((alert) => (
                <tr
                  key={alert.id}
                  onClick={() => navigate('/alerts')}
                  style={{ cursor: 'pointer' }}
                >
                  <td>
                    <SeverityTag severity={alert.severity} />
                  </td>
                  <td
                    style={{
                      maxWidth: 220,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      fontWeight: 500,
                    }}
                    title={alert.title}
                  >
                    {alert.title}
                  </td>
                  <td style={{ color: 'var(--tx-muted)' }}>{alert.source}</td>
                  <td style={{ color: 'var(--tx-muted)', fontFamily: 'var(--font-mono)' }}>
                    {alert.asset ?? '—'}
                  </td>
                  <td>
                    <StatusTag status={alert.status} />
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                    {alert.risk_score}
                  </td>
                  <td style={{ color: 'var(--tx-muted)' }}>{relativeTime(alert.detected_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <Card title="Response performance" accent="gold">
          <Stat
            label="MTTR"
            value={data.mttr_minutes !== null ? `${data.mttr_minutes} min` : '—'}
          />
          <Stat label="Incidents resolved (30d)" value={data.incident_metrics.resolved} />
          <Stat
            label="MTTR p90"
            value={
              data.incident_metrics.mttr_p90_minutes !== null
                ? `${data.incident_metrics.mttr_p90_minutes} min`
                : '—'
            }
          />
          <Stat
            label="Critical open"
            value={data.incident_metrics.critical_open}
            tone="var(--red)"
          />
        </Card>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>
        <Card
          title="Alert distribution"
          accent="navy"
          actions={
            <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              Last {data.alert_distribution.window_hours}h · {data.alert_distribution.total} total
            </span>
          }
        >
          {SEVERITY_ORDER.map((severity) => {
            const count = data.alert_distribution.counts[severity] ?? 0;
            const percent = data.alert_distribution.total
              ? (count / data.alert_distribution.total) * 100
              : 0;
            return (
              <div className="sev-row" key={severity}>
                <span className="sev-label" style={{ color: SEVERITY_COLOUR[severity] }}>
                  {severity}
                </span>
                <div className="sev-bar-track">
                  <div
                    className="sev-bar-fill"
                    style={{ width: `${percent}%`, background: SEVERITY_COLOUR[severity] }}
                  />
                </div>
                <span className="sev-count">{count}</span>
              </div>
            );
          })}
          <div style={{ borderTop: '1px solid var(--br-light)', paddingTop: 9, marginTop: 3 }}>
            <div
              style={{
                fontSize: 9,
                color: 'var(--tx-muted)',
                marginBottom: 5,
                fontFamily: 'var(--font-mono)',
                fontWeight: 700,
                textTransform: 'uppercase',
              }}
            >
              Automation rate
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div
                style={{
                  flex: 1,
                  height: 8,
                  background: 'var(--bg-sunken)',
                  borderRadius: 4,
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${data.alert_distribution.automation_rate}%`,
                    height: '100%',
                    background: 'linear-gradient(90deg, var(--navy), var(--gold))',
                    borderRadius: 4,
                  }}
                />
              </div>
              <span
                style={{
                  fontFamily: 'var(--font-head)',
                  fontSize: 18,
                  fontWeight: 700,
                  color: 'var(--navy)',
                }}
              >
                {data.alert_distribution.automation_rate}%
              </span>
            </div>
            <div style={{ fontSize: 9.5, color: 'var(--tx-muted)', marginTop: 3 }}>
              {data.alert_distribution.automated} of {data.alert_distribution.total} alerts resolved
              without an analyst
            </div>
          </div>
        </Card>

        <Card
          title="Integration health"
          accent="gold"
          actions={
            <span style={{ fontSize: 9, color: 'var(--tx-muted)' }}>
              {data.integration_health.total} services
            </span>
          }
        >
          <div className="health-grid-3" style={{ marginBottom: 9 }}>
            {data.integration_health.integrations.slice(0, 12).map((integration) => (
              <div
                className="health-item-sm"
                key={integration.slug}
                title={integration.last_error ?? ''}
              >
                <HealthDot health={integration.health} />
                {integration.name}
              </div>
            ))}
          </div>
          <div
            style={{
              borderTop: '1px solid var(--br-light)',
              paddingTop: 8,
              display: 'flex',
              gap: 12,
            }}
          >
            <span style={{ fontSize: 9.5, color: 'var(--tx-muted)' }}>
              <span style={{ color: 'var(--green)' }}>●</span> {data.integration_health.healthy}{' '}
              healthy
            </span>
            <span style={{ fontSize: 9.5, color: 'var(--tx-muted)' }}>
              <span style={{ color: 'var(--amber)' }}>●</span> {data.integration_health.degraded}{' '}
              degraded
            </span>
            <span style={{ fontSize: 9.5, color: 'var(--tx-muted)' }}>
              <span style={{ color: 'var(--red)' }}>●</span> {data.integration_health.offline}{' '}
              offline
            </span>
          </div>
        </Card>

        <Card title="Tool usage" accent="navy">
          {data.tool_usage.length === 0 ? (
            <div
              style={{
                fontSize: 10.5,
                color: 'var(--tx-muted)',
                padding: '18px 4px',
                textAlign: 'center',
              }}
            >
              No tool executions recorded yet.
            </div>
          ) : (
            data.tool_usage.slice(0, 8).map((tool) => (
              <div className="exec-row" key={tool.tool_name}>
                <span className="exec-tool">{tool.tool_name}</span>
                <span style={{ marginLeft: 'auto', fontSize: 10, fontFamily: 'var(--font-mono)' }}>
                  {formatNumber(tool.calls)}
                </span>
                <span
                  style={{
                    fontSize: 10,
                    color: tool.success_rate >= 95 ? 'var(--green)' : 'var(--amber)',
                    width: 44,
                    textAlign: 'right',
                  }}
                >
                  {tool.success_rate}%
                </span>
              </div>
            ))
          )}
        </Card>
      </div>
    </div>
  );
}

function MetricTiles({
  metrics,
  onNavigate,
}: {
  metrics: DashboardMetrics;
  onNavigate: (to: string) => void;
}) {
  const tiles = [
    {
      label: 'Critical alerts',
      value: metrics.critical_alerts,
      cls: 'critical',
      colour: 'var(--red)',
      icon: '⚠',
      bg: 'var(--red-x)',
      to: '/alerts',
    },
    {
      label: 'Open incidents',
      value: metrics.open_incidents,
      cls: 'high',
      colour: 'var(--amber)',
      icon: '🚨',
      bg: 'var(--amber-x)',
      to: '/incidents',
    },
    {
      label: 'Auto-resolved (24h)',
      value: metrics.auto_resolved,
      cls: 'medium',
      colour: 'var(--navy)',
      icon: '⚡',
      bg: 'var(--navy-muted)',
      to: '/playbooks',
    },
    {
      label: 'MTTR (minutes)',
      value: metrics.mttr_minutes !== null ? Math.round(metrics.mttr_minutes) : '—',
      cls: 'low',
      colour: 'var(--green)',
      icon: '⏱',
      bg: 'var(--green-x)',
      to: '/incidents',
    },
  ];

  return (
    <div className="metrics-grid">
      {tiles.map((tile) => (
        <div
          className={`metric-card ${tile.cls}`}
          key={tile.label}
          onClick={() => onNavigate(tile.to)}
          style={{ cursor: 'pointer' }}
        >
          <div className="metric-icon" style={{ background: tile.bg }}>
            {tile.icon}
          </div>
          <div className="metric-label">{tile.label}</div>
          <div className="metric-value" style={{ color: tile.colour }}>
            {tile.value}
          </div>
        </div>
      ))}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '7px 9px',
        background: 'var(--bg-raised)',
        border: '1px solid var(--br-light)',
        borderRadius: 'var(--r)',
        marginBottom: 6,
      }}
    >
      <span style={{ fontSize: 10.5, color: 'var(--tx-secondary)' }}>{label}</span>
      <span
        style={{
          fontFamily: 'var(--font-head)',
          fontSize: 16,
          fontWeight: 700,
          color: tone ?? 'var(--navy)',
        }}
      >
        {value}
      </span>
    </div>
  );
}
