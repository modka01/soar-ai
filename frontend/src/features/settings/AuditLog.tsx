import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { platform } from '@/api/resources';
import { Button, ErrorBanner, Spinner, Tag } from '@/components/primitives';
import { formatDateTime, truncate } from '@/lib/format';

const PAGE_SIZE = 50;

export function AuditLog() {
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);

  const log = useQuery({
    queryKey: ['audit', search, offset],
    queryFn: () => platform.audit({ search: search || undefined, limit: PAGE_SIZE, offset }),
  });

  return (
    <div className="s-section">
      <div className="s-section-title">Audit log</div>
      <p style={{ fontSize: 10.5, color: 'var(--tx-muted)', marginBottom: 10, lineHeight: 1.6 }}>
        Append-only record of every privileged action. Entries are never edited or deleted by the
        platform — retention policy archives them instead.
      </p>

      <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
        <input
          type="search"
          value={search}
          placeholder="Search by actor, action or resource…"
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
          style={{ flex: 1, fontSize: 10 }}
          aria-label="Search audit log"
        />
      </div>

      {log.error && <ErrorBanner error={log.error} onRetry={() => void log.refetch()} />}
      {log.isLoading ? (
        <Spinner />
      ) : (
        <table className="tbl">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Source IP</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {log.data?.items.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  style={{ textAlign: 'center', color: 'var(--tx-muted)', padding: 20 }}
                >
                  No audit entries match this filter.
                </td>
              </tr>
            )}
            {log.data?.items.map((entry) => (
              <tr key={entry.id}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 9.5 }}>
                  {formatDateTime(entry.created_at)}
                </td>
                <td
                  style={{
                    color: entry.actor_type === 'system' ? 'var(--navy)' : 'var(--tx-primary)',
                    fontWeight: entry.actor_type === 'system' ? 600 : 400,
                  }}
                >
                  {truncate(entry.actor, 28)}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--navy)' }}>
                  {entry.action}
                </td>
                <td
                  style={{
                    color: 'var(--tx-muted)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 9.5,
                  }}
                >
                  {entry.resource_id ?? '—'}
                </td>
                <td style={{ color: 'var(--tx-muted)', fontSize: 9.5 }}>
                  {entry.source_ip ?? '—'}
                </td>
                <td>
                  <Tag tone={entry.outcome === 'success' ? 'green' : 'red'}>{entry.outcome}</Tag>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center' }}>
        <Button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}>
          ← Previous
        </Button>
        <span style={{ fontSize: 10, color: 'var(--tx-muted)' }}>
          {offset + 1}–{Math.min(offset + PAGE_SIZE, log.data?.total ?? 0)} of{' '}
          {log.data?.total ?? 0}
        </span>
        <Button
          onClick={() => setOffset(offset + PAGE_SIZE)}
          disabled={offset + PAGE_SIZE >= (log.data?.total ?? 0)}
        >
          Next →
        </Button>
      </div>
    </div>
  );
}
