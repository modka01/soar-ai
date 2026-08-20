import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { aws } from '@/api/resources';
import { Button, Card, ErrorBanner, SeverityTag, Spinner, Tag } from '@/components/primitives';
import { Modal } from '@/components/Modal';
import { relativeTime, truncate } from '@/lib/format';
import { toastError, useToasts } from '@/lib/store';

interface PendingRemediation {
  action: string;
  resourceId: string;
  label: string;
}

export function AwsSecurity() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);
  const [pending, setPending] = useState<PendingRemediation | null>(null);

  const overview = useQuery({ queryKey: ['aws', 'overview'], queryFn: () => aws.overview() });
  const findings = useQuery({
    queryKey: ['aws', 'findings'],
    queryFn: () => aws.findings({ limit: 50 }),
  });
  const iam = useQuery({ queryKey: ['aws', 'iam'], queryFn: aws.iamRisks, retry: false });
  const buckets = useQuery({
    queryKey: ['aws', 'buckets'],
    queryFn: aws.publicBuckets,
    retry: false,
  });

  const sync = useMutation({
    mutationFn: () => aws.sync(),
    onSuccess: (result) => {
      push(result.message);
      void queryClient.invalidateQueries({ queryKey: ['aws'] });
    },
    onError: (error) => toastError(error, 'AWS sync failed.'),
  });

  const remediate = useMutation({
    mutationFn: () =>
      aws.remediate(pending!.action, pending!.resourceId, 'Remediated from the SOAR console'),
    onSuccess: (result) => {
      const dryRun = (result as { dry_run?: boolean }).dry_run;
      push(
        dryRun
          ? 'Dry run complete — nothing was changed in AWS.'
          : 'Remediation applied successfully.',
        dryRun ? 'warning' : 'success',
      );
      setPending(null);
      void queryClient.invalidateQueries({ queryKey: ['aws'] });
    },
    onError: (error) => toastError(error, 'Remediation failed.'),
  });

  const cloudUnavailable = overview.error && findings.data?.items.length === 0;

  return (
    <div className="scroll-area">
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center' }}>
        <span style={{ fontSize: 11, fontWeight: 600 }}>AWS account</span>
        <span style={{ fontSize: 11, color: 'var(--navy)', fontFamily: 'var(--font-mono)' }}>
          {overview.data?.account_id ?? 'not configured'}
        </span>
        {overview.data?.region && <Tag tone="green">{overview.data.region}</Tag>}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <Button onClick={() => sync.mutate()} disabled={sync.isPending}>
            {sync.isPending ? 'Syncing…' : '↻ Sync findings'}
          </Button>
        </div>
      </div>

      {cloudUnavailable && (
        <div className="highlight-box" style={{ marginBottom: 14 }}>
          <strong>AWS is not reachable.</strong> Attach an IAM role or credentials with read access
          to GuardDuty, Security Hub, IAM and S3, then sync again. Nothing below is fabricated — an
          empty panel means the platform has no data for it.
        </div>
      )}

      {overview.isLoading ? (
        <Spinner label="Reading cloud posture…" />
      ) : (
        <div className="aws-grid">
          {overview.data?.services.map((service) => (
            <div className="aws-service" key={service.name}>
              <div className="aws-svc-head">
                <span style={{ fontSize: 18 }}>{service.icon}</span>
                <div>
                  <div className="aws-svc-name">{service.name}</div>
                  <div style={{ fontSize: 8, color: 'var(--tx-muted)' }}>{service.region}</div>
                </div>
              </div>
              {service.metrics.map((metric) => (
                <div className="aws-metric" key={metric.label}>
                  <span style={{ fontSize: 9.5, color: 'var(--tx-muted)' }}>{metric.label}</span>
                  <span className="aws-metric-val" style={{ color: `var(--${metric.tone})` }}>
                    {metric.value}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 4 }}>
        <Card
          title="GuardDuty findings"
          accent="navy"
          bodyClassName=""
          actions={<Tag tone="amber">{findings.data?.total ?? 0} active</Tag>}
        >
          <div style={{ maxHeight: 300, overflowY: 'auto' }}>
            {findings.error && <ErrorBanner error={findings.error} />}
            {findings.data?.items.length === 0 && (
              <div className="empty-state">
                <div className="empty-state-title">No active findings</div>
                <div>Run a sync to pull the latest from GuardDuty.</div>
              </div>
            )}
            {findings.data?.items.map((finding) => (
              <div className="exec-row" key={finding.id}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 500 }}>
                    {truncate(finding.finding_type, 48)}
                  </div>
                  <div
                    style={{ fontSize: 9, color: 'var(--navy)', fontFamily: 'var(--font-mono)' }}
                  >
                    {finding.resource_id ?? '—'} · {finding.region ?? '—'} ·{' '}
                    {relativeTime(finding.created_at)}
                  </div>
                </div>
                <SeverityTag severity={finding.severity} />
                {finding.status === 'active' && finding.resource_id && (
                  <Button
                    variant="danger"
                    style={{ fontSize: 9, padding: '2px 8px' }}
                    onClick={() =>
                      setPending({
                        action: guessAction(finding.finding_type),
                        resourceId: finding.resource_id!,
                        label: finding.finding_type,
                      })
                    }
                  >
                    Fix
                  </Button>
                )}
              </div>
            ))}
          </div>
        </Card>

        <Card
          title="IAM risk analysis"
          accent="gold"
          bodyClassName=""
          actions={<Tag tone="red">{iam.data?.total ?? 0} issues</Tag>}
        >
          <div style={{ maxHeight: 300, overflowY: 'auto' }}>
            {iam.error && (
              <div style={{ padding: 14, fontSize: 10.5, color: 'var(--tx-muted)' }}>
                IAM analysis needs read access to the IAM API.
              </div>
            )}
            {iam.data?.risks.map((risk, index) => (
              <div className="exec-row" key={`${risk.principal}-${index}`}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 10.5,
                      fontWeight: 500,
                      color: 'var(--navy)',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {risk.principal}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--tx-muted)' }}>{risk.risk}</div>
                </div>
                <SeverityTag severity={risk.severity} />
                <Button
                  style={{ fontSize: 9, padding: '2px 7px' }}
                  title={risk.remediation}
                  onClick={() =>
                    setPending({
                      action: 'revoke_iam',
                      resourceId: risk.principal,
                      label: `${risk.principal}: ${risk.risk}`,
                    })
                  }
                >
                  Fix
                </Button>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {buckets.data && buckets.data.total > 0 && (
        <Card title="Publicly accessible S3 buckets" accent="navy" bodyClassName="">
          {buckets.data.buckets.map((bucket) => (
            <div className="exec-row" key={bucket.bucket}>
              <span
                style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5, color: 'var(--navy)' }}
              >
                {bucket.bucket}
              </span>
              <span style={{ flex: 1, fontSize: 9, color: 'var(--tx-muted)' }}>
                {bucket.reason}
              </span>
              <Button
                variant="danger"
                style={{ fontSize: 9, padding: '2px 8px' }}
                onClick={() =>
                  setPending({
                    action: 'block_s3',
                    resourceId: bucket.bucket,
                    label: `Block public access on ${bucket.bucket}`,
                  })
                }
              >
                Block public access
              </Button>
            </div>
          ))}
        </Card>
      )}

      <Modal
        open={pending !== null}
        title="Confirm AWS remediation"
        onClose={() => setPending(null)}
        onConfirm={() => remediate.mutate()}
        confirmLabel="Apply remediation"
        confirmVariant="danger"
        busy={remediate.isPending}
      >
        <p style={{ fontSize: 11.5, color: 'var(--tx-secondary)', lineHeight: 1.75 }}>
          This changes live cloud infrastructure.
        </p>
        <div
          style={{
            background: 'var(--bg-raised)',
            border: '1px solid var(--br-mid)',
            borderRadius: 'var(--r)',
            padding: 12,
            margin: '10px 0',
            fontSize: 11,
          }}
        >
          <div>
            <strong>Action:</strong> <code style={{ color: 'var(--navy)' }}>{pending?.action}</code>
          </div>
          <div style={{ marginTop: 4 }}>
            <strong>Resource:</strong>{' '}
            <code style={{ color: 'var(--navy)' }}>{pending?.resourceId}</code>
          </div>
          <div style={{ marginTop: 4, color: 'var(--tx-muted)' }}>{pending?.label}</div>
        </div>
        <p style={{ fontSize: 10.5, color: 'var(--tx-muted)', lineHeight: 1.6 }}>
          If the platform runs with destructive actions disabled, this executes as a dry run and
          reports what it would have changed. Either way the action is recorded in the audit log.
        </p>
      </Modal>
    </div>
  );
}

/** Pick the remediation that matches a GuardDuty finding type. */
function guessAction(findingType: string): string {
  if (findingType.includes('S3')) return 'block_s3';
  if (findingType.includes('IAMUser')) return 'revoke_iam';
  if (findingType.includes('EC2')) return 'snapshot_ec2';
  return 'block_sg';
}
