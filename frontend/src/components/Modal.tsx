import { useEffect, useRef, type ReactNode } from 'react';
import { Button } from './primitives';
import logo from '@/assets/quantnexa-logo.jpg';

/**
 * Focus-trapping modal. Escape closes, focus returns to the trigger on close,
 * and a backdrop click only dismisses when it originates on the backdrop.
 */
export function Modal({
  open,
  title,
  onClose,
  onConfirm,
  confirmLabel = 'Confirm',
  confirmVariant = 'navy',
  busy = false,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  onConfirm?: () => void;
  confirmLabel?: string;
  confirmVariant?: 'navy' | 'gold' | 'danger';
  busy?: boolean;
  children: ReactNode;
}) {
  const boxRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    previouslyFocused.current = document.activeElement as HTMLElement | null;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
        return;
      }
      if (event.key !== 'Tab' || !boxRef.current) return;

      const focusable = boxRef.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown);
    boxRef.current?.querySelector<HTMLElement>('input, textarea, button')?.focus();

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      previouslyFocused.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="modal-backdrop open"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="modal" ref={boxRef} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-header">
          <img src={logo} className="modal-logo" alt="" />
          <div className="modal-title">{title}</div>
        </div>
        <div>{children}</div>
        <div
          style={{
            display: 'flex',
            gap: 8,
            marginTop: 18,
            justifyContent: 'flex-end',
            paddingTop: 14,
            borderTop: '1px solid var(--br-light)',
          }}
        >
          <Button onClick={onClose}>Cancel</Button>
          {onConfirm && (
            <Button variant={confirmVariant} onClick={onConfirm} disabled={busy}>
              {busy ? 'Working…' : confirmLabel}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
