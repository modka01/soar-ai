import { describe, expect, it } from 'vitest';
import {
  formatDuration,
  formatNumber,
  healthClass,
  relativeTime,
  renderMarkdown,
  severityTone,
  statusTone,
  truncate,
} from './format';

describe('tone mapping', () => {
  it('maps each severity to its brand tone', () => {
    expect(severityTone('critical')).toBe('red');
    expect(severityTone('high')).toBe('amber');
    expect(severityTone('medium')).toBe('blue');
    expect(severityTone('low')).toBe('green');
    expect(severityTone('anything-else')).toBe('gray');
  });

  it('maps workflow states to tones', () => {
    expect(statusTone('open')).toBe('red');
    expect(statusTone('investigating')).toBe('amber');
    expect(statusTone('closed')).toBe('green');
  });

  it('maps health states to the dot class', () => {
    expect(healthClass('healthy')).toBe('ok');
    expect(healthClass('degraded')).toBe('warn');
    expect(healthClass('offline')).toBe('err');
  });
});

describe('formatting', () => {
  it('formats durations at each scale', () => {
    expect(formatDuration(420)).toBe('420ms');
    expect(formatDuration(4200)).toBe('4.2s');
    expect(formatDuration(125_000)).toBe('2m 5s');
  });

  it('abbreviates large numbers', () => {
    expect(formatNumber(847)).toBe('847');
    expect(formatNumber(2847)).toBe('2.8K');
    expect(formatNumber(1_200_000)).toBe('1.2M');
  });

  it('truncates with an ellipsis only when needed', () => {
    expect(truncate('short', 10)).toBe('short');
    expect(truncate('a'.repeat(20), 10)).toHaveLength(10);
  });

  it('renders recency, not wall-clock time', () => {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60_000).toISOString();
    expect(relativeTime(fiveMinutesAgo)).toBe('5 min ago');
    expect(relativeTime(null)).toBe('—');
    expect(relativeTime('not-a-date')).toBe('—');
  });
});

describe('renderMarkdown', () => {
  it('renders the agent markdown subset', () => {
    const html = renderMarkdown(
      '## Findings\n**Critical** issue in `lsass.exe`\n- Isolate the host',
    );
    expect(html).toContain('<h3 class="md-h3">Findings</h3>');
    expect(html).toContain('<strong>Critical</strong>');
    expect(html).toContain('<code class="md-code">lsass.exe</code>');
    expect(html).toContain('md-li');
  });

  it('escapes markup before formatting, so tool output cannot inject HTML', () => {
    const html = renderMarkdown('<img src=x onerror="alert(1)">');
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
  });

  it('escapes markup nested inside a formatting marker', () => {
    const html = renderMarkdown('**<script>alert(1)</script>**');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });
});
