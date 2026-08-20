/** The application shell: sidebar navigation, top bar, and the routed outlet. */

import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { dashboard } from '@/api/resources';
import { useAuth } from '@/lib/store';
import logo from '@/assets/quantnexa-logo.jpg';
import { Toasts } from './Toasts';

interface NavEntry {
  to: string;
  label: string;
  icon: JSX.Element;
  /** Which live counter, if any, renders as the nav pill. */
  badge?: 'critical' | 'incidents';
  pill?: { text: string; tone: string };
}

interface NavGroup {
  label: string;
  entries: NavEntry[];
}

const icon = (path: JSX.Element) => (
  <svg className="nav-ico" fill="none" viewBox="0 0 14 14" stroke="currentColor" strokeWidth={1.5}>
    {path}
  </svg>
);

const NAV: NavGroup[] = [
  {
    label: 'Core Operations',
    entries: [
      {
        to: '/agent',
        label: 'Agent Console',
        pill: { text: 'AI', tone: 'gold' },
        icon: icon(
          <>
            <circle cx="7" cy="5" r="3" />
            <path d="M1 13c0-3.3 2.7-5 6-5s6 1.7 6 5" />
          </>,
        ),
      },
      {
        to: '/dashboard',
        label: 'Dashboard',
        icon: icon(
          <>
            <rect x="1" y="1" width="5" height="5" rx="1" />
            <rect x="8" y="1" width="5" height="5" rx="1" />
            <rect x="1" y="8" width="5" height="5" rx="1" />
            <rect x="8" y="8" width="5" height="5" rx="1" />
          </>,
        ),
      },
      {
        to: '/incidents',
        label: 'Incidents',
        badge: 'incidents',
        icon: icon(
          <>
            <path d="M7 2L1 11h12L7 2z" />
            <path d="M7 6v3M7 10.5v.5" />
          </>,
        ),
      },
      {
        to: '/sigma',
        label: 'Sigma Builder',
        pill: { text: 'GEN', tone: 'green' },
        icon: icon(
          <>
            <path d="M2 2h10M2 7h6M2 12h4" />
            <circle cx="11" cy="10" r="2.5" />
          </>,
        ),
      },
      {
        to: '/aws',
        label: 'AWS Security',
        icon: icon(
          <path d="M3.5 9h7a1 1 0 0 1 0 2h-7a1 1 0 0 1 0-2zM7 3a2.5 2.5 0 0 0-2.5 2.5M7 3a2.5 2.5 0 0 1 2.5 2.5" />,
        ),
      },
      {
        to: '/alerts',
        label: 'Alert Queue',
        badge: 'critical',
        icon: icon(
          <>
            <path d="M7 1C4.2 1 2 3.2 2 6v4l-1 1.5h12L12 10V6C12 3.2 9.8 1 7 1z" />
            <path d="M5.5 12.5C5.5 13.3 6.2 14 7 14s1.5-.7 1.5-1.5" />
          </>,
        ),
      },
      {
        to: '/playbooks',
        label: 'Playbooks',
        icon: icon(
          <>
            <path d="M2 2h10v10H2z" />
            <path d="M5 5h4M5 7.5h4M5 10h2" />
          </>,
        ),
      },
    ],
  },
  {
    label: 'Intelligence',
    entries: [
      {
        to: '/knowledge',
        label: 'RAG Knowledge',
        icon: icon(
          <>
            <rect x="2" y="2" width="4" height="4" rx="1" />
            <rect x="8" y="2" width="4" height="4" rx="1" />
            <rect x="2" y="8" width="4" height="4" rx="1" />
            <rect x="8" y="8" width="4" height="4" rx="1" />
          </>,
        ),
      },
      {
        to: '/tools',
        label: 'MCP Tools',
        icon: icon(
          <>
            <circle cx="3" cy="7" r="2" />
            <circle cx="11" cy="3" r="2" />
            <circle cx="11" cy="11" r="2" />
            <path d="M5 7h2l2-4M5 7h2l2 4" />
          </>,
        ),
      },
      {
        to: '/threats',
        label: 'Threat Intel',
        icon: icon(
          <>
            <circle cx="7" cy="7" r="6" />
            <path d="M7 4v4M7 10v.5" />
          </>,
        ),
      },
      {
        to: '/workflows',
        label: 'n8n Workflows',
        icon: icon(
          <>
            <rect x="1" y="5" width="4" height="4" rx="1" />
            <rect x="9" y="1" width="4" height="4" rx="1" />
            <rect x="9" y="9" width="4" height="4" rx="1" />
            <path d="M5 7h2l2-2M5 7h2l2 2" />
          </>,
        ),
      },
    ],
  },
  {
    label: 'System',
    entries: [
      {
        to: '/settings',
        label: 'Settings',
        icon: icon(
          <>
            <circle cx="7" cy="7" r="2.5" />
            <path d="M7 1v1.5M7 11.5V13M1 7h1.5M11.5 7H13M2.9 2.9l1.1 1.1M10 10l1.1 1.1M2.9 11.1L4 10M10 4l1.1-1.1" />
          </>,
        ),
      },
    ],
  },
];

const TITLES: Record<string, { title: string; badge: string }> = {
  '/agent': { title: 'AGENT CONSOLE', badge: 'AGENTIC · RAG · MCP' },
  '/dashboard': { title: 'DASHBOARD', badge: 'LIVE OPERATIONS' },
  '/incidents': { title: 'INCIDENTS', badge: 'LIVE QUEUE' },
  '/alerts': { title: 'ALERT QUEUE', badge: 'TRIAGE' },
  '/knowledge': { title: 'RAG KNOWLEDGE BASE', badge: 'VECTOR RETRIEVAL' },
  '/tools': { title: 'MCP TOOL REGISTRY', badge: 'AUDITED CAPABILITIES' },
  '/sigma': { title: 'SIGMA BUILDER', badge: 'AI RULE GENERATION' },
  '/aws': { title: 'AWS SECURITY', badge: 'CLOUD POSTURE' },
  '/playbooks': { title: 'PLAYBOOKS', badge: 'n8n ORCHESTRATION' },
  '/workflows': { title: 'n8n WORKFLOWS', badge: 'AUTOMATION ENGINE' },
  '/threats': { title: 'THREAT INTELLIGENCE', badge: 'IOC ENRICHMENT' },
  '/settings': { title: 'SETTINGS', badge: 'PLATFORM CONFIG' },
};

function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{now.toUTCString().slice(17, 25)} UTC</span>;
}

export function Shell() {
  const location = useLocation();
  const { user, logout } = useAuth();

  // Nav badges reflect live counts; a failed poll must not break navigation.
  const { data: metrics } = useQuery({
    queryKey: ['dashboard', 'nav-badges'],
    queryFn: () => dashboard.metrics(24),
    refetchInterval: 60_000,
    retry: 1,
  });

  const badgeValue = (kind: NavEntry['badge']): number | undefined => {
    if (!metrics) return undefined;
    if (kind === 'critical') return metrics.critical_alerts;
    if (kind === 'incidents') return metrics.open_incidents;
    return undefined;
  };

  const header = TITLES[location.pathname] ?? { title: 'SOAR·AI', badge: '' };
  const healthy = metrics?.integration_health;
  const allOperational = healthy ? healthy.offline === 0 : true;

  return (
    <>
      <div className="qn-accent-strip" />
      <div className="shell">
        <aside className="sidebar">
          <div className="sidebar-logo">
            <img src={logo} alt="QuantNexa Technologies" className="logo-img-full" />
            <div className="logo-tagline">SOAR · AI Platform</div>
          </div>

          {NAV.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-section-label">{group.label}</div>
              {group.entries.map((entry) => {
                const count = badgeValue(entry.badge);
                return (
                  <NavLink
                    key={entry.to}
                    to={entry.to}
                    className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                  >
                    {entry.icon}
                    <span>{entry.label}</span>
                    {entry.pill && (
                      <span className={`nav-pill pill-${entry.pill.tone}`}>{entry.pill.text}</span>
                    )}
                    {count !== undefined && count > 0 && (
                      <span className="nav-pill pill-red">{count}</span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          ))}

          <div className="sidebar-footer">
            <div className="sys-status">
              <div className="pulse-dot" />
              {allOperational
                ? 'All systems operational'
                : `${healthy?.offline} integration offline`}
            </div>
            <div
              style={{
                fontSize: 8,
                color: 'rgba(253,199,14,0.4)',
                marginTop: 4,
                fontFamily: 'var(--font-mono)',
              }}
            >
              v{__APP_VERSION__} · RAG + MCP
            </div>
          </div>
        </aside>

        <div className="main">
          <div className="topbar">
            <img src={logo} alt="" className="topbar-logomark" />
            <div className="topbar-divider" />
            <div className="topbar-module">{header.title}</div>
            {header.badge && <div className="topbar-badge">{header.badge}</div>}
            <div className="topbar-right">
              <Clock />
              {user && (
                <span
                  style={{ fontSize: 10, color: 'var(--tx-muted)' }}
                  title={`Signed in as ${user.email}`}
                >
                  {user.full_name} · {user.role.replace(/_/g, ' ')}
                </span>
              )}
              <button className="btn" onClick={logout}>
                Sign out
              </button>
            </div>
          </div>

          <div className="content-area">
            <Outlet />
          </div>
        </div>
      </div>
      <Toasts />
    </>
  );
}
