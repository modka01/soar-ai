import { useQuery } from '@tanstack/react-query';
import { auth } from '@/api/resources';
import { ErrorBanner, Spinner, Tag } from '@/components/primitives';
import { relativeTime } from '@/lib/format';

export function UsersPanel() {
  const users = useQuery({ queryKey: ['users'], queryFn: () => auth.listUsers(100) });

  return (
    <div className="s-section">
      <div className="s-section-title">Users and roles</div>
      <p style={{ fontSize: 10.5, color: 'var(--tx-muted)', marginBottom: 10, lineHeight: 1.6 }}>
        A role grants a fixed permission set. An API key issued by a user can narrow that set but
        never widen it.
      </p>

      {users.error && <ErrorBanner error={users.error} onRetry={() => void users.refetch()} />}
      {users.isLoading ? (
        <Spinner />
      ) : (
        <table className="tbl">
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>MFA</th>
              <th>Status</th>
              <th>Last login</th>
            </tr>
          </thead>
          <tbody>
            {users.data?.items.map((user) => (
              <tr key={user.id}>
                <td>
                  <div style={{ fontWeight: 600 }}>{user.full_name}</div>
                  <div
                    style={{
                      fontSize: 9,
                      color: 'var(--tx-muted)',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {user.email}
                  </div>
                </td>
                <td>
                  <Tag tone="navy">{user.role.replace(/_/g, ' ')}</Tag>
                </td>
                <td style={{ color: user.mfa_enabled ? 'var(--green)' : 'var(--red)' }}>●</td>
                <td>
                  <Tag tone={user.is_active ? 'green' : 'red'}>
                    {user.is_active ? 'active' : 'disabled'}
                  </Tag>
                </td>
                <td style={{ color: 'var(--tx-muted)', fontSize: 9.5 }}>
                  {relativeTime(user.last_login_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
