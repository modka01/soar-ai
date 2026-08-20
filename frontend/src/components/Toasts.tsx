import { useToasts } from '@/lib/store';

const ICONS = { success: '✓', error: '✗', warning: '⚠' } as const;
const COLOURS = {
  success: 'var(--green)',
  error: 'var(--red)',
  warning: 'var(--amber)',
} as const;

export function Toasts() {
  const { toasts, dismiss } = useToasts();
  if (toasts.length === 0) return null;

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 20,
        right: 20,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        zIndex: 'var(--z-toast)' as never,
      }}
      aria-live="polite"
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className="toast"
          onClick={() => dismiss(toast.id)}
          style={{ borderLeft: `3px solid ${COLOURS[toast.tone]}`, cursor: 'pointer' }}
          role="status"
        >
          <span style={{ color: COLOURS[toast.tone], fontWeight: 700 }}>{ICONS[toast.tone]}</span>
          <span>{toast.message}</span>
        </div>
      ))}
    </div>
  );
}
