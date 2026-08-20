import { lazy, Suspense, useEffect } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { Shell } from '@/components/Shell';
import { Spinner } from '@/components/primitives';
import { Login } from '@/features/auth/Login';
import { queryClient } from '@/lib/queryClient';
import { useAuth } from '@/lib/store';

// Split each module so the initial console load stays small — an analyst who
// only opens the Agent Console never downloads the Sigma editor.
const AgentConsole = lazy(() =>
  import('@/features/agent/AgentConsole').then((m) => ({ default: m.AgentConsole })),
);
const Dashboard = lazy(() =>
  import('@/features/dashboard/Dashboard').then((m) => ({ default: m.Dashboard })),
);
const AlertQueue = lazy(() =>
  import('@/features/alerts/AlertQueue').then((m) => ({ default: m.AlertQueue })),
);
const Incidents = lazy(() =>
  import('@/features/incidents/Incidents').then((m) => ({ default: m.Incidents })),
);
const Knowledge = lazy(() =>
  import('@/features/knowledge/Knowledge').then((m) => ({ default: m.Knowledge })),
);
const McpTools = lazy(() =>
  import('@/features/tools/McpTools').then((m) => ({ default: m.McpTools })),
);
const SigmaBuilder = lazy(() =>
  import('@/features/sigma/SigmaBuilder').then((m) => ({ default: m.SigmaBuilder })),
);
const AwsSecurity = lazy(() =>
  import('@/features/aws/AwsSecurity').then((m) => ({ default: m.AwsSecurity })),
);
const Playbooks = lazy(() =>
  import('@/features/playbooks/Playbooks').then((m) => ({ default: m.Playbooks })),
);
const Workflows = lazy(() =>
  import('@/features/workflows/Workflows').then((m) => ({ default: m.Workflows })),
);
const ThreatIntel = lazy(() =>
  import('@/features/threats/ThreatIntel').then((m) => ({ default: m.ThreatIntel })),
);
const Settings = lazy(() =>
  import('@/features/settings/Settings').then((m) => ({ default: m.Settings })),
);

export function App() {
  const { status, restore } = useAuth();

  useEffect(() => {
    void restore();
  }, [restore]);

  if (status === 'unknown') return <Spinner label="Restoring your session…" />;
  if (status === 'anonymous') return <Login />;

  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Navigate to="/agent" replace />} />
        <Route
          path="/agent"
          element={
            <Suspense fallback={<Spinner />}>
              <AgentConsole />
            </Suspense>
          }
        />
        <Route
          path="/dashboard"
          element={
            <Suspense fallback={<Spinner />}>
              <Dashboard />
            </Suspense>
          }
        />
        <Route
          path="/alerts"
          element={
            <Suspense fallback={<Spinner />}>
              <AlertQueue />
            </Suspense>
          }
        />
        <Route
          path="/incidents"
          element={
            <Suspense fallback={<Spinner />}>
              <Incidents />
            </Suspense>
          }
        />
        <Route
          path="/knowledge"
          element={
            <Suspense fallback={<Spinner />}>
              <Knowledge />
            </Suspense>
          }
        />
        <Route
          path="/tools"
          element={
            <Suspense fallback={<Spinner />}>
              <McpTools />
            </Suspense>
          }
        />
        <Route
          path="/sigma"
          element={
            <Suspense fallback={<Spinner />}>
              <SigmaBuilder />
            </Suspense>
          }
        />
        <Route
          path="/aws"
          element={
            <Suspense fallback={<Spinner />}>
              <AwsSecurity />
            </Suspense>
          }
        />
        <Route
          path="/playbooks"
          element={
            <Suspense fallback={<Spinner />}>
              <Playbooks />
            </Suspense>
          }
        />
        <Route
          path="/workflows"
          element={
            <Suspense fallback={<Spinner />}>
              <Workflows />
            </Suspense>
          }
        />
        <Route
          path="/threats"
          element={
            <Suspense fallback={<Spinner />}>
              <ThreatIntel />
            </Suspense>
          }
        />
        <Route
          path="/settings"
          element={
            <Suspense fallback={<Spinner />}>
              <Settings />
            </Suspense>
          }
        />
        <Route path="*" element={<Navigate to="/agent" replace />} />
      </Route>
    </Routes>
  );
}

export function Root() {
  return (
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  );
}
