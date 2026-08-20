import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { threats } from '@/api/resources';
import { Button, Card, ErrorBanner, Spinner, Tag } from '@/components/primitives';
import { relativeTime, truncate } from '@/lib/format';
import { toastError, useToasts } from '@/lib/store';

const TYPE_ICON: Record<string, string> = {
  ip: '🌐',
  domain: '🔗',
  url: '🔗',
  hash: '📄',
  email: '📧',
  cve: '⚠️',
};

function verdictTone(verdict: string): string {
  if (verdict === 'malicious') return 'red';
  if (verdict === 'suspicious') return 'amber';
  if (verdict === 'clean') return 'green';
  return 'gray';
}

export function ThreatIntel() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);
  const [value, setValue] = useState('');

  const feed = useQuery({
    queryKey: ['threats', 'feed'],
    queryFn: () => threats.feed(60),
    refetchInterval: 60_000,
  });
  const stats = useQuery({ queryKey: ['threats', 'stats'], queryFn: threats.stats });

  const enrich = useMutation({
    mutationFn: (indicator: string) => threats.enrich(indicator, true),
    onSuccess: (indicator) => {
      push(
        `${indicator.value} → ${indicator.verdict} (${indicator.confidence}% confidence)`,
        indicator.verdict === 'malicious' ? 'warning' : 'success',
      );
      setValue('');
      void queryClient.invalidateQueries({ queryKey: ['threats'] });
    },
    onError: (error) => toastError(error, 'Enrichment failed.'),
  });

  return (
    <div className="scroll-area">
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, alignItems: 'center' }}>
        <input
          type="text"
          value={value}
          placeholder="Enrich an IP, domain, URL, hash or CVE…"
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && value.trim()) enrich.mutate(value.trim());
          }}
          style={{ flex: 1, fontSize: 11 }}
          aria-label="Indicator to enrich"
        />
        <Button
          variant="navy"
          onClick={() => value.trim() && enrich.mutate(value.trim())}
          disabled={!value.trim() || enrich.isPending}
        >
          {enrich.isPending ? 'Enriching…' : '🔍 Enrich'}
        </Button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div>
          <div
            style={{
              fontSize: 9,
              color: 'var(--tx-muted)',
              textTransform: 'uppercase',
              letterSpacing: '1px',
              marginBottom: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
            }}
          >
            Indicator feed
          </div>
          {feed.error && <ErrorBanner error={feed.error} onRetry={() => void feed.refetch()} />}
          {feed.isLoading && <Spinner />}
          {feed.data?.length === 0 && (
            <div className="empty-state">
              <div className="empty-state-title">No indicators yet</div>
              <div>
                Enrich an IOC above, or let the agent populate the feed while it works incidents.
              </div>
            </div>
          )}
          <div className="threat-feed">
            {feed.data?.map((indicator) => (
              <div className="threat-item" key={indicator.id}>
                <div className="threat-icon">{TYPE_ICON[indicator.indicator_type] ?? '•'}</div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="threat-ioc">{truncate(indicator.value, 46)}</div>
                  <div className="threat-desc">
                    {indicator.description ??
                      `${indicator.indicator_type.toUpperCase()} · ${indicator.sources.join(', ') || 'no source'}`}
                  </div>
                  {indicator.threat_actors.length > 0 && (
                    <div style={{ display: 'flex', gap: 4, marginTop: 3 }}>
                      {indicator.threat_actors.slice(0, 3).map((actor) => (
                        <Tag tone="red" key={actor}>
                          {actor}
                        </Tag>
                      ))}
                    </div>
                  )}
                </div>
                <div style={{ textAlign: 'right' }}>
                  <Tag tone={verdictTone(indicator.verdict)}>{indicator.verdict}</Tag>
                  <div className="threat-score">{indicator.confidence}</div>
                  <div style={{ fontSize: 8.5, color: 'var(--tx-muted)' }}>
                    {relativeTime(indicator.last_seen)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div>
          {stats.data && (
            <>
              <Card title="Verdict breakdown" accent="navy">
                {Object.entries(stats.data.by_verdict).map(([verdict, count]) => (
                  <div className="sev-row" key={verdict}>
                    <span className="sev-label" style={{ color: `var(--${verdictTone(verdict)})` }}>
                      {verdict}
                    </span>
                    <div className="sev-bar-track">
                      <div
                        className="sev-bar-fill"
                        style={{
                          width: `${stats.data!.total ? (count / stats.data!.total) * 100 : 0}%`,
                          background: `var(--${verdictTone(verdict)})`,
                        }}
                      />
                    </div>
                    <span className="sev-count">{count}</span>
                  </div>
                ))}
              </Card>

              <Card title="Top threat actors" accent="gold" bodyClassName="">
                {stats.data.top_actors.length === 0 && (
                  <div style={{ padding: 14, fontSize: 10.5, color: 'var(--tx-muted)' }}>
                    No actor attribution recorded yet.
                  </div>
                )}
                {stats.data.top_actors.map((actor) => (
                  <div className="exec-row" key={actor.actor}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--navy)' }}>
                      {actor.actor}
                    </span>
                    <span
                      style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10 }}
                    >
                      {actor.count} IOC{actor.count === 1 ? '' : 's'}
                    </span>
                  </div>
                ))}
              </Card>

              <Card title="By indicator type" accent="navy" bodyClassName="">
                {Object.entries(stats.data.by_type).map(([type, count]) => (
                  <div className="exec-row" key={type}>
                    <span>{TYPE_ICON[type] ?? '•'}</span>
                    <span style={{ fontSize: 10.5 }}>{type}</span>
                    <span
                      style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10 }}
                    >
                      {count}
                    </span>
                  </div>
                ))}
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
