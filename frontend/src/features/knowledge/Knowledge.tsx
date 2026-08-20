import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { rag } from '@/api/resources';
import { Button, Card, ErrorBanner, Spinner, Tag } from '@/components/primitives';
import { Modal } from '@/components/Modal';
import { truncate } from '@/lib/format';
import { toastError, useToasts } from '@/lib/store';
import type { RetrievalHit } from '@/types/api';

const CATEGORY_TONE: Record<string, string> = {
  'Command and Control': 'navy',
  'Lateral Movement': 'amber',
  'Credential Access': 'red',
  Impact: 'red',
  'Initial Access': 'cyan',
  Cloud: 'blue',
  'Cloud Misconfiguration': 'amber',
  Detection: 'green',
  Response: 'navy',
  APT: 'red',
  Vulnerability: 'amber',
  Architecture: 'gray',
};

export function Knowledge() {
  const queryClient = useQueryClient();
  const push = useToasts((state) => state.push);
  const [search, setSearch] = useState('');
  const [probe, setProbe] = useState('');
  const [hits, setHits] = useState<RetrievalHit[] | null>(null);
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState({
    title: '',
    source: '',
    category: 'Threat Intel',
    content: '',
  });

  const chunks = useQuery({
    queryKey: ['rag', 'chunks', search],
    queryFn: () => rag.chunks({ search: search || undefined, limit: 200 }),
  });
  const stats = useQuery({ queryKey: ['rag', 'stats'], queryFn: rag.stats });

  const retrieve = useMutation({
    mutationFn: (query: string) => rag.retrieve(query, 5),
    onSuccess: setHits,
    onError: (error) => toastError(error, 'Retrieval failed.'),
  });

  const addDocument = useMutation({
    mutationFn: () => rag.addDocument(draft),
    onSuccess: () => {
      push('Document chunked and indexed.');
      setAdding(false);
      setDraft({ title: '', source: '', category: 'Threat Intel', content: '' });
      void queryClient.invalidateQueries({ queryKey: ['rag'] });
    },
    onError: (error) => toastError(error, 'Indexing failed.'),
  });

  return (
    <div className="scroll-area">
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, alignItems: 'center' }}>
        <input
          type="search"
          value={search}
          placeholder="Search the knowledge base…"
          onChange={(event) => setSearch(event.target.value)}
          style={{ flex: 1, fontSize: 11 }}
          aria-label="Search knowledge base"
        />
        <Button variant="navy" onClick={() => setAdding(true)}>
          + Add document
        </Button>
      </div>

      <div className="rag-layout">
        <div>
          <div
            style={{
              fontSize: 9,
              color: 'var(--tx-muted)',
              textTransform: 'uppercase',
              letterSpacing: '1px',
              marginBottom: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
            }}
          >
            Knowledge chunks ({stats.data?.total_chunks ?? 0} indexed)
          </div>

          {chunks.error && (
            <ErrorBanner error={chunks.error} onRetry={() => void chunks.refetch()} />
          )}
          {chunks.isLoading ? (
            <Spinner />
          ) : (
            chunks.data?.items.map((chunk) => (
              <div className="kb-chunk" key={chunk.id}>
                <div className="kb-chunk-head">
                  <Tag tone={CATEGORY_TONE[chunk.category] ?? 'gray'}>{chunk.category}</Tag>
                  <span className="kb-source">{chunk.source}</span>
                  <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--tx-muted)' }}>
                    {chunk.token_count} tokens
                  </span>
                </div>
                <div className="kb-chunk-title">{chunk.title}</div>
                <div className="kb-chunk-text">{truncate(chunk.text, 260)}</div>
              </div>
            ))
          )}
          {chunks.data?.items.length === 0 && (
            <div className="empty-state">
              <div className="empty-state-title">Nothing indexed</div>
              <div>Add a document, or run the platform seeder from Settings.</div>
            </div>
          )}
        </div>

        <div>
          <Card title="Test retrieval" accent="gold">
            <p style={{ fontSize: 10, color: 'var(--tx-muted)', marginBottom: 8, lineHeight: 1.6 }}>
              Run a query through the same retriever the agent uses, and see exactly which chunks
              would be injected into its prompt.
            </p>
            <div style={{ display: 'flex', gap: 6 }}>
              <input
                type="text"
                value={probe}
                placeholder="e.g. PsExec lateral movement"
                onChange={(event) => setProbe(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && probe.trim()) retrieve.mutate(probe.trim());
                }}
                style={{ flex: 1, fontSize: 10.5 }}
                aria-label="Retrieval query"
              />
              <Button
                variant="navy"
                onClick={() => probe.trim() && retrieve.mutate(probe.trim())}
                disabled={retrieve.isPending}
              >
                Retrieve
              </Button>
            </div>

            {hits && (
              <div style={{ marginTop: 10 }}>
                {hits.length === 0 && (
                  <div style={{ fontSize: 10, color: 'var(--tx-muted)' }}>
                    Nothing scored above the relevance floor.
                  </div>
                )}
                {hits.map((hit) => (
                  <div className="rag-context-item" key={hit.chunk_id}>
                    <div className="rag-context-head">
                      <span className="rag-source">{hit.source}</span>
                      <span className="rag-score">{(hit.score * 100).toFixed(0)}%</span>
                    </div>
                    <div className="rag-context-title">{hit.title}</div>
                    <div className="rag-context-text">{truncate(hit.text, 180)}</div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {stats.data && (
            <Card title="Index statistics" accent="navy">
              <StatRow label="Documents" value={stats.data.total_documents} />
              <StatRow label="Chunks" value={stats.data.total_chunks} />
              <StatRow label="Avg tokens / chunk" value={stats.data.avg_tokens_per_chunk} />
              <StatRow label="Embedding model" value={stats.data.embedding_model} />
              <StatRow label="Dimensions" value={stats.data.dimensions} />
              <StatRow label="Top-K" value={stats.data.top_k} />

              <div
                style={{
                  fontSize: 9,
                  color: 'var(--tx-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '1px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  margin: '12px 0 6px',
                }}
              >
                Sources
              </div>
              {stats.data.by_source.map((entry) => (
                <div className="exec-row" key={entry.source}>
                  <span style={{ fontSize: 10.5 }}>{entry.source}</span>
                  <span
                    style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10 }}
                  >
                    {entry.count}
                  </span>
                </div>
              ))}
            </Card>
          )}
        </div>
      </div>

      <Modal
        open={adding}
        title="Add knowledge document"
        onClose={() => setAdding(false)}
        onConfirm={() => addDocument.mutate()}
        confirmLabel="Index document"
        busy={addDocument.isPending}
      >
        <div className="s-field">
          <label className="s-label" htmlFor="doc-title">
            Title
          </label>
          <input
            id="doc-title"
            className="s-input-wide"
            value={draft.title}
            placeholder="e.g. APT-41 TTPs 2026"
            onChange={(event) => setDraft({ ...draft, title: event.target.value })}
          />
        </div>
        <div className="s-field">
          <label className="s-label" htmlFor="doc-source">
            Source
          </label>
          <input
            id="doc-source"
            className="s-input-wide"
            value={draft.source}
            placeholder="e.g. Mandiant report"
            onChange={(event) => setDraft({ ...draft, source: event.target.value })}
          />
        </div>
        <div className="s-field">
          <label className="s-label" htmlFor="doc-category">
            Category
          </label>
          <select
            id="doc-category"
            className="s-input-wide"
            value={draft.category}
            onChange={(event) => setDraft({ ...draft, category: event.target.value })}
          >
            {[
              'Threat Intel',
              'MITRE ATT&CK',
              'Response',
              'Vulnerability',
              'Detection',
              'Cloud',
            ].map((option) => (
              <option key={option}>{option}</option>
            ))}
          </select>
        </div>
        <div className="s-field">
          <label className="s-label" htmlFor="doc-content">
            Content
          </label>
          <textarea
            id="doc-content"
            className="s-input-wide"
            rows={6}
            value={draft.content}
            placeholder="Paste the content to be chunked and embedded…"
            onChange={(event) => setDraft({ ...draft, content: event.target.value })}
          />
        </div>
      </Modal>
    </div>
  );
}

function StatRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        padding: '5px 8px',
        background: 'var(--bg-raised)',
        border: '1px solid var(--br-light)',
        borderRadius: 'var(--r)',
        marginBottom: 5,
      }}
    >
      <span style={{ fontSize: 10, color: 'var(--tx-secondary)' }}>{label}</span>
      <span
        style={{
          fontSize: 10,
          fontFamily: 'var(--font-mono)',
          color: 'var(--navy)',
          fontWeight: 600,
        }}
      >
        {value}
      </span>
    </div>
  );
}
