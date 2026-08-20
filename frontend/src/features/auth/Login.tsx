import { useState, type FormEvent } from 'react';
import { useAuth } from '@/lib/store';
import logo from '@/assets/quantnexa-logo.jpg';

export function Login() {
  const { login, error } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      await login(email, password);
    } catch {
      // The store holds the error message; the banner below renders it.
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-shell">
      <form className="login-card" onSubmit={submit}>
        <img src={logo} alt="QuantNexa Technologies" className="login-logo" />
        <div className="login-title">SOAR · AI Platform</div>
        <div className="login-sub">Security operations console</div>

        {error && (
          <div className="error-banner" role="alert">
            <span>⚠</span>
            <div>{error}</div>
          </div>
        )}

        <div className="login-field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={email}
            autoComplete="username"
            required
            onChange={(event) => setEmail(event.target.value)}
          />
        </div>

        <div className="login-field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            autoComplete="current-password"
            required
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>

        <button className="btn btn-navy login-submit" type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        <div style={{ marginTop: 16, fontSize: 9, color: 'var(--tx-muted)', textAlign: 'center' }}>
          Authorised access only. All activity is recorded in the audit log.
        </div>
      </form>
    </div>
  );
}
