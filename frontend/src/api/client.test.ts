import { describe, expect, it, vi, beforeEach } from 'vitest';
import { ApiError, buildUrl, parseFrame, request, tokenStore } from './client';

describe('buildUrl', () => {
  it('omits empty and undefined query values', () => {
    const url = buildUrl('/alerts', { severity: 'critical', status: undefined, search: '' });
    expect(url).toContain('severity=critical');
    expect(url).not.toContain('status');
    expect(url).not.toContain('search');
  });

  it('encodes values that need escaping', () => {
    expect(buildUrl('/alerts', { search: 'C2 & beacon' })).toContain('search=C2+%26+beacon');
  });
});

describe('tokenStore', () => {
  beforeEach(() => localStorage.clear());

  it('round-trips and clears a token pair', () => {
    tokenStore.set({ access_token: 'a', refresh_token: 'r', token_type: 'bearer', expires_in: 60 });
    expect(tokenStore.access).toBe('a');
    tokenStore.clear();
    expect(tokenStore.access).toBeNull();
  });
});

describe('ApiError', () => {
  it('parses the backend error envelope', () => {
    const error = new ApiError(
      403,
      {
        error: {
          code: 'forbidden',
          message: 'Role soc_l1 is missing approval:decide.',
          details: {},
          request_id: 'req-1',
        },
      },
      'fallback',
    );
    expect(error.code).toBe('forbidden');
    expect(error.isForbidden).toBe(true);
    expect(error.requestId).toBe('req-1');
  });

  it('classifies which failures are worth retrying', () => {
    expect(new ApiError(503, null, 'x').isRetryable).toBe(true);
    expect(new ApiError(429, null, 'x').isRetryable).toBe(true);
    expect(new ApiError(422, null, 'x').isRetryable).toBe(false);
    expect(new ApiError(401, null, 'x').isAuthError).toBe(true);
  });
});

describe('parseFrame', () => {
  it('parses a typed SSE frame', () => {
    expect(parseFrame('event: tool_result\ndata: {"tool":"query_siem","ok":true}')).toEqual({
      event: 'tool_result',
      data: { tool: 'query_siem', ok: true },
    });
  });

  it('ignores keep-alive comments', () => {
    expect(parseFrame(': keep-alive')).toBeNull();
  });

  it('defaults the event name when only data is sent', () => {
    expect(parseFrame('data: {"x":1}')?.event).toBe('message');
  });
});

describe('request', () => {
  beforeEach(() => localStorage.clear());

  it('attaches the bearer token when one is stored', async () => {
    tokenStore.set({
      access_token: 'tok',
      refresh_token: 'r',
      token_type: 'bearer',
      expires_in: 60,
    });
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await request('/alerts');

    const headers = fetchMock.mock.calls[0]![1].headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer tok');
  });

  it('refreshes once and replays the request after a 401', async () => {
    tokenStore.set({
      access_token: 'stale',
      refresh_token: 'r',
      token_type: 'bearer',
      expires_in: 60,
    });
    const json = (body: unknown, status: number) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      });

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ error: { code: 'unauthenticated' } }, 401))
      .mockResolvedValueOnce(
        json(
          { access_token: 'fresh', refresh_token: 'r2', token_type: 'bearer', expires_in: 60 },
          200,
        ),
      )
      .mockResolvedValueOnce(json({ items: [] }, 200));
    vi.stubGlobal('fetch', fetchMock);

    await request('/alerts');

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(tokenStore.access).toBe('fresh');
  });

  it('clears the session when the refresh itself fails', async () => {
    tokenStore.set({
      access_token: 'stale',
      refresh_token: 'r',
      token_type: 'bearer',
      expires_in: 60,
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('{}', { status: 401 }))
      .mockResolvedValueOnce(new Response('{}', { status: 401 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(request('/alerts')).rejects.toBeInstanceOf(ApiError);
    expect(tokenStore.access).toBeNull();
  });

  it('surfaces the backend error message', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code: 'validation_error',
              message: 'severity is invalid',
              details: {},
              request_id: null,
            },
          }),
          { status: 422, headers: { 'content-type': 'application/json' } },
        ),
      ),
    );

    await expect(request('/alerts/ingest', { method: 'POST', body: {} })).rejects.toThrow(
      'severity is invalid',
    );
  });
});
