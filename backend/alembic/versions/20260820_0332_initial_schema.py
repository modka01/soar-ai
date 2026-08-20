"""Initial schema for the QuantNexa SOAR·AI platform.

Creates every table: users and API keys, the audit trail, alerts and incidents,
agent sessions with approvals and tool executions, the RAG knowledge base,
Sigma rules and deployments, playbooks, workflows, threat indicators, cloud
findings, integrations and settings.

Revision ID: a44be17e92c3
Revises: 
Create Date: 2026-08-20 03:32:13.368661+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

import app.db.base  # noqa: F401 - JSONBType is referenced in column definitions


revision: str = 'a44be17e92c3'
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table('audit_logs',
    sa.Column('actor', sa.String(length=200), nullable=False),
    sa.Column('actor_type', sa.String(length=32), nullable=False),
    sa.Column('action', sa.String(length=120), nullable=False),
    sa.Column('resource_type', sa.String(length=64), nullable=True),
    sa.Column('resource_id', sa.String(length=120), nullable=True),
    sa.Column('outcome', sa.String(length=16), nullable=False),
    sa.Column('source_ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.Text(), nullable=True),
    sa.Column('request_id', sa.String(length=64), nullable=True),
    sa.Column('detail', app.db.base.JSONBType(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_logs'))
    )
    op.create_index('ix_audit_logs_action_created', 'audit_logs', ['action', 'created_at'], unique=False)
    op.create_index('ix_audit_logs_actor_created', 'audit_logs', ['actor', 'created_at'], unique=False)
    op.create_index(op.f('ix_audit_logs_created_at'), 'audit_logs', ['created_at'], unique=False)
    op.create_index(op.f('ix_audit_logs_request_id'), 'audit_logs', ['request_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_resource_id'), 'audit_logs', ['resource_id'], unique=False)
    op.create_table('cloud_findings',
    sa.Column('provider', sa.String(length=24), nullable=False),
    sa.Column('service', sa.String(length=60), nullable=False),
    sa.Column('finding_type', sa.String(length=300), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('account_id', sa.String(length=32), nullable=True),
    sa.Column('region', sa.String(length=32), nullable=True),
    sa.Column('resource_id', sa.String(length=500), nullable=True),
    sa.Column('resource_type', sa.String(length=120), nullable=True),
    sa.Column('external_id', sa.String(length=500), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('remediation', sa.Text(), nullable=True),
    sa.Column('remediated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('raw', app.db.base.JSONBType(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_cloud_findings'))
    )
    op.create_index(op.f('ix_cloud_findings_account_id'), 'cloud_findings', ['account_id'], unique=False)
    op.create_index(op.f('ix_cloud_findings_created_at'), 'cloud_findings', ['created_at'], unique=False)
    op.create_index(op.f('ix_cloud_findings_external_id'), 'cloud_findings', ['external_id'], unique=True)
    op.create_index(op.f('ix_cloud_findings_region'), 'cloud_findings', ['region'], unique=False)
    op.create_index(op.f('ix_cloud_findings_service'), 'cloud_findings', ['service'], unique=False)
    op.create_index('ix_cloud_findings_service_severity', 'cloud_findings', ['service', 'severity'], unique=False)
    op.create_index(op.f('ix_cloud_findings_severity'), 'cloud_findings', ['severity'], unique=False)
    op.create_index(op.f('ix_cloud_findings_status'), 'cloud_findings', ['status'], unique=False)
    op.create_table('incidents',
    sa.Column('reference', sa.String(length=32), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('asset', sa.String(length=255), nullable=True),
    sa.Column('owner', sa.String(length=200), nullable=True),
    sa.Column('ai_summary', sa.Text(), nullable=True),
    sa.Column('mitre_techniques', app.db.base.JSONBType(), nullable=False),
    sa.Column('indicators', app.db.base.JSONBType(), nullable=False),
    sa.Column('tags', app.db.base.JSONBType(), nullable=False),
    sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('contained_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('external_ticket_id', sa.String(length=120), nullable=True),
    sa.Column('external_ticket_url', sa.String(length=500), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incidents'))
    )
    op.create_index(op.f('ix_incidents_asset'), 'incidents', ['asset'], unique=False)
    op.create_index(op.f('ix_incidents_created_at'), 'incidents', ['created_at'], unique=False)
    op.create_index(op.f('ix_incidents_owner'), 'incidents', ['owner'], unique=False)
    op.create_index(op.f('ix_incidents_reference'), 'incidents', ['reference'], unique=True)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index('ix_incidents_severity_status', 'incidents', ['severity', 'status'], unique=False)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_table('integrations',
    sa.Column('slug', sa.String(length=80), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('category', sa.String(length=60), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('health', sa.String(length=16), nullable=False),
    sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('latency_ms', sa.Float(), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('config', app.db.base.JSONBType(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_integrations'))
    )
    op.create_index(op.f('ix_integrations_category'), 'integrations', ['category'], unique=False)
    op.create_index(op.f('ix_integrations_created_at'), 'integrations', ['created_at'], unique=False)
    op.create_index(op.f('ix_integrations_health'), 'integrations', ['health'], unique=False)
    op.create_index(op.f('ix_integrations_slug'), 'integrations', ['slug'], unique=True)
    op.create_table('knowledge_documents',
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('source', sa.String(length=120), nullable=False),
    sa.Column('category', sa.String(length=80), nullable=False),
    sa.Column('url', sa.String(length=1000), nullable=True),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('chunk_count', sa.Integer(), nullable=False),
    sa.Column('meta', app.db.base.JSONBType(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_knowledge_documents'))
    )
    op.create_index(op.f('ix_knowledge_documents_category'), 'knowledge_documents', ['category'], unique=False)
    op.create_index(op.f('ix_knowledge_documents_content_hash'), 'knowledge_documents', ['content_hash'], unique=False)
    op.create_index(op.f('ix_knowledge_documents_created_at'), 'knowledge_documents', ['created_at'], unique=False)
    op.create_index(op.f('ix_knowledge_documents_source'), 'knowledge_documents', ['source'], unique=False)
    op.create_table('playbooks',
    sa.Column('slug', sa.String(length=80), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('icon', sa.String(length=16), nullable=False),
    sa.Column('estimated_seconds', sa.Integer(), nullable=False),
    sa.Column('n8n_workflow_id', sa.String(length=120), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('requires_approval', sa.Boolean(), nullable=False),
    sa.Column('steps', app.db.base.JSONBType(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_playbooks'))
    )
    op.create_index(op.f('ix_playbooks_created_at'), 'playbooks', ['created_at'], unique=False)
    op.create_index(op.f('ix_playbooks_slug'), 'playbooks', ['slug'], unique=True)
    op.create_table('settings',
    sa.Column('namespace', sa.String(length=60), nullable=False),
    sa.Column('key', sa.String(length=80), nullable=False),
    sa.Column('value', app.db.base.JSONBType(), nullable=False),
    sa.Column('is_secret', sa.Boolean(), nullable=False),
    sa.Column('updated_by', sa.String(length=200), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('namespace', 'key', name=op.f('pk_settings'))
    )
    op.create_index(op.f('ix_settings_created_at'), 'settings', ['created_at'], unique=False)
    op.create_table('threat_indicators',
    sa.Column('value', sa.String(length=500), nullable=False),
    sa.Column('indicator_type', sa.String(length=16), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('verdict', sa.String(length=24), nullable=False),
    sa.Column('confidence', sa.Integer(), nullable=False),
    sa.Column('threat_actors', app.db.base.JSONBType(), nullable=False),
    sa.Column('mitre_techniques', app.db.base.JSONBType(), nullable=False),
    sa.Column('sources', app.db.base.JSONBType(), nullable=False),
    sa.Column('enrichment', app.db.base.JSONBType(), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_threat_indicators'))
    )
    op.create_index(op.f('ix_threat_indicators_created_at'), 'threat_indicators', ['created_at'], unique=False)
    op.create_index(op.f('ix_threat_indicators_indicator_type'), 'threat_indicators', ['indicator_type'], unique=False)
    op.create_index(op.f('ix_threat_indicators_last_seen'), 'threat_indicators', ['last_seen'], unique=False)
    op.create_index(op.f('ix_threat_indicators_value'), 'threat_indicators', ['value'], unique=False)
    op.create_index('ix_threat_indicators_value_type', 'threat_indicators', ['value', 'indicator_type'], unique=True)
    op.create_index(op.f('ix_threat_indicators_verdict'), 'threat_indicators', ['verdict'], unique=False)
    op.create_table('users',
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('full_name', sa.String(length=200), nullable=False),
    sa.Column('hashed_password', sa.String(length=255), nullable=True),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('mfa_enabled', sa.Boolean(), nullable=False),
    sa.Column('mfa_secret', sa.String(length=64), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('failed_login_count', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users'))
    )
    op.create_index(op.f('ix_users_created_at'), 'users', ['created_at'], unique=False)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_table('workflow_runs',
    sa.Column('workflow_id', sa.String(length=120), nullable=False),
    sa.Column('workflow_name', sa.String(length=200), nullable=False),
    sa.Column('execution_id', sa.String(length=120), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('trigger_source', sa.String(length=120), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('node_results', app.db.base.JSONBType(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_workflow_runs'))
    )
    op.create_index(op.f('ix_workflow_runs_created_at'), 'workflow_runs', ['created_at'], unique=False)
    op.create_index(op.f('ix_workflow_runs_execution_id'), 'workflow_runs', ['execution_id'], unique=False)
    op.create_index(op.f('ix_workflow_runs_status'), 'workflow_runs', ['status'], unique=False)
    op.create_index(op.f('ix_workflow_runs_workflow_id'), 'workflow_runs', ['workflow_id'], unique=False)
    op.create_table('agent_sessions',
    sa.Column('task', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('created_by', sa.String(length=200), nullable=False),
    sa.Column('model', sa.String(length=80), nullable=False),
    sa.Column('iterations', sa.Integer(), nullable=False),
    sa.Column('max_iterations', sa.Integer(), nullable=False),
    sa.Column('plan', app.db.base.JSONBType(), nullable=False),
    sa.Column('plan_cursor', sa.Integer(), nullable=False),
    sa.Column('final_answer', sa.Text(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('rag_chunk_ids', app.db.base.JSONBType(), nullable=False),
    sa.Column('input_tokens', sa.Integer(), nullable=False),
    sa.Column('output_tokens', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_agent_sessions_incident_id_incidents'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agent_sessions'))
    )
    op.create_index(op.f('ix_agent_sessions_created_at'), 'agent_sessions', ['created_at'], unique=False)
    op.create_index(op.f('ix_agent_sessions_created_by'), 'agent_sessions', ['created_by'], unique=False)
    op.create_index(op.f('ix_agent_sessions_incident_id'), 'agent_sessions', ['incident_id'], unique=False)
    op.create_index(op.f('ix_agent_sessions_status'), 'agent_sessions', ['status'], unique=False)
    op.create_index('ix_agent_sessions_status_created', 'agent_sessions', ['status', 'created_at'], unique=False)
    op.create_table('alerts',
    sa.Column('reference', sa.String(length=32), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('source', sa.String(length=80), nullable=False),
    sa.Column('source_event_id', sa.String(length=200), nullable=True),
    sa.Column('asset', sa.String(length=255), nullable=True),
    sa.Column('asset_type', sa.String(length=40), nullable=True),
    sa.Column('risk_score', sa.Integer(), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('ai_triaged', sa.Boolean(), nullable=False),
    sa.Column('ai_summary', sa.Text(), nullable=True),
    sa.Column('mitre_techniques', app.db.base.JSONBType(), nullable=False),
    sa.Column('indicators', app.db.base.JSONBType(), nullable=False),
    sa.Column('raw_event', app.db.base.JSONBType(), nullable=False),
    sa.Column('dedup_key', sa.String(length=64), nullable=True),
    sa.Column('duplicate_count', sa.Integer(), nullable=False),
    sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('assignee', sa.String(length=200), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_alerts_incident_id_incidents'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_alerts'))
    )
    op.create_index(op.f('ix_alerts_asset'), 'alerts', ['asset'], unique=False)
    op.create_index(op.f('ix_alerts_created_at'), 'alerts', ['created_at'], unique=False)
    op.create_index('ix_alerts_dedup', 'alerts', ['dedup_key', 'created_at'], unique=False)
    op.create_index(op.f('ix_alerts_dedup_key'), 'alerts', ['dedup_key'], unique=False)
    op.create_index(op.f('ix_alerts_incident_id'), 'alerts', ['incident_id'], unique=False)
    op.create_index(op.f('ix_alerts_reference'), 'alerts', ['reference'], unique=True)
    op.create_index(op.f('ix_alerts_risk_score'), 'alerts', ['risk_score'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index('ix_alerts_severity_status', 'alerts', ['severity', 'status'], unique=False)
    op.create_index(op.f('ix_alerts_source'), 'alerts', ['source'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_table('api_keys',
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('key_prefix', sa.String(length=24), nullable=False),
    sa.Column('key_hash', sa.String(length=64), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('scopes', app.db.base.JSONBType(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_api_keys_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_api_keys'))
    )
    op.create_index(op.f('ix_api_keys_created_at'), 'api_keys', ['created_at'], unique=False)
    op.create_index(op.f('ix_api_keys_key_hash'), 'api_keys', ['key_hash'], unique=True)
    op.create_index(op.f('ix_api_keys_key_prefix'), 'api_keys', ['key_prefix'], unique=False)
    op.create_table('incident_events',
    sa.Column('incident_id', sa.String(length=36), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('kind', sa.String(length=40), nullable=False),
    sa.Column('actor', sa.String(length=200), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('tool_name', sa.String(length=80), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('detail', app.db.base.JSONBType(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_incident_events_incident_id_incidents'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incident_events'))
    )
    op.create_index(op.f('ix_incident_events_created_at'), 'incident_events', ['created_at'], unique=False)
    op.create_index(op.f('ix_incident_events_incident_id'), 'incident_events', ['incident_id'], unique=False)
    op.create_table('knowledge_chunks',
    sa.Column('document_id', sa.String(length=36), nullable=True),
    sa.Column('external_id', sa.String(length=120), nullable=True),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('source', sa.String(length=120), nullable=False),
    sa.Column('category', sa.String(length=80), nullable=False),
    sa.Column('text', sa.Text(), nullable=False),
    sa.Column('token_count', sa.Integer(), nullable=False),
    sa.Column('embedding', app.db.base.JSONBType(), nullable=False),
    sa.Column('embedding_model', sa.String(length=80), nullable=False),
    sa.Column('meta', app.db.base.JSONBType(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['document_id'], ['knowledge_documents.id'], name=op.f('fk_knowledge_chunks_document_id_knowledge_documents'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_knowledge_chunks'))
    )
    op.create_index(op.f('ix_knowledge_chunks_category'), 'knowledge_chunks', ['category'], unique=False)
    op.create_index(op.f('ix_knowledge_chunks_created_at'), 'knowledge_chunks', ['created_at'], unique=False)
    op.create_index(op.f('ix_knowledge_chunks_document_id'), 'knowledge_chunks', ['document_id'], unique=False)
    op.create_index(op.f('ix_knowledge_chunks_external_id'), 'knowledge_chunks', ['external_id'], unique=True)
    op.create_index(op.f('ix_knowledge_chunks_source'), 'knowledge_chunks', ['source'], unique=False)
    op.create_index('ix_knowledge_chunks_source_category', 'knowledge_chunks', ['source', 'category'], unique=False)
    op.create_table('sigma_rules',
    sa.Column('reference', sa.String(length=32), nullable=False),
    sa.Column('rule_uuid', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=300), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('tactic', sa.String(length=80), nullable=False),
    sa.Column('log_source', sa.String(length=80), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('yaml_body', sa.Text(), nullable=False),
    sa.Column('mitre_techniques', app.db.base.JSONBType(), nullable=False),
    sa.Column('false_positives', app.db.base.JSONBType(), nullable=False),
    sa.Column('author', sa.String(length=200), nullable=False),
    sa.Column('ai_generated', sa.Boolean(), nullable=False),
    sa.Column('source_incident_id', sa.String(length=36), nullable=True),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['source_incident_id'], ['incidents.id'], name=op.f('fk_sigma_rules_source_incident_id_incidents'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sigma_rules')),
    sa.UniqueConstraint('rule_uuid', name=op.f('uq_sigma_rules_rule_uuid'))
    )
    op.create_index(op.f('ix_sigma_rules_created_at'), 'sigma_rules', ['created_at'], unique=False)
    op.create_index(op.f('ix_sigma_rules_reference'), 'sigma_rules', ['reference'], unique=True)
    op.create_index(op.f('ix_sigma_rules_severity'), 'sigma_rules', ['severity'], unique=False)
    op.create_index(op.f('ix_sigma_rules_status'), 'sigma_rules', ['status'], unique=False)
    op.create_index(op.f('ix_sigma_rules_tactic'), 'sigma_rules', ['tactic'], unique=False)
    op.create_index('ix_sigma_rules_tactic_severity', 'sigma_rules', ['tactic', 'severity'], unique=False)
    op.create_table('agent_messages',
    sa.Column('session_id', sa.String(length=36), nullable=False),
    sa.Column('sequence', sa.Integer(), nullable=False),
    sa.Column('role', sa.String(length=24), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('is_final', sa.Boolean(), nullable=False),
    sa.Column('citations', app.db.base.JSONBType(), nullable=False),
    sa.Column('meta', app.db.base.JSONBType(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['session_id'], ['agent_sessions.id'], name=op.f('fk_agent_messages_session_id_agent_sessions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agent_messages'))
    )
    op.create_index(op.f('ix_agent_messages_created_at'), 'agent_messages', ['created_at'], unique=False)
    op.create_index(op.f('ix_agent_messages_session_id'), 'agent_messages', ['session_id'], unique=False)
    op.create_index('ix_agent_messages_session_seq', 'agent_messages', ['session_id', 'sequence'], unique=False)
    op.create_table('approval_requests',
    sa.Column('session_id', sa.String(length=36), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('requested_actions', app.db.base.JSONBType(), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=False),
    sa.Column('decided_by', sa.String(length=200), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('decision_note', sa.Text(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['session_id'], ['agent_sessions.id'], name=op.f('fk_approval_requests_session_id_agent_sessions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_approval_requests'))
    )
    op.create_index(op.f('ix_approval_requests_created_at'), 'approval_requests', ['created_at'], unique=False)
    op.create_index(op.f('ix_approval_requests_session_id'), 'approval_requests', ['session_id'], unique=False)
    op.create_index(op.f('ix_approval_requests_status'), 'approval_requests', ['status'], unique=False)
    op.create_table('playbook_runs',
    sa.Column('playbook_id', sa.String(length=36), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('alert_id', sa.String(length=36), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('triggered_by', sa.String(length=200), nullable=False),
    sa.Column('current_step', sa.Integer(), nullable=False),
    sa.Column('total_steps', sa.Integer(), nullable=False),
    sa.Column('step_results', app.db.base.JSONBType(), nullable=False),
    sa.Column('n8n_execution_id', sa.String(length=120), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('dry_run', sa.Boolean(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], name=op.f('fk_playbook_runs_alert_id_alerts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_playbook_runs_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['playbook_id'], ['playbooks.id'], name=op.f('fk_playbook_runs_playbook_id_playbooks'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_playbook_runs'))
    )
    op.create_index(op.f('ix_playbook_runs_created_at'), 'playbook_runs', ['created_at'], unique=False)
    op.create_index(op.f('ix_playbook_runs_incident_id'), 'playbook_runs', ['incident_id'], unique=False)
    op.create_index(op.f('ix_playbook_runs_playbook_id'), 'playbook_runs', ['playbook_id'], unique=False)
    op.create_index(op.f('ix_playbook_runs_status'), 'playbook_runs', ['status'], unique=False)
    op.create_index('ix_playbook_runs_status_created', 'playbook_runs', ['status', 'created_at'], unique=False)
    op.create_table('rule_deployments',
    sa.Column('rule_id', sa.String(length=36), nullable=False),
    sa.Column('backend', sa.String(length=60), nullable=False),
    sa.Column('converted_query', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('deployed_by', sa.String(length=200), nullable=False),
    sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('external_id', sa.String(length=200), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['rule_id'], ['sigma_rules.id'], name=op.f('fk_rule_deployments_rule_id_sigma_rules'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_rule_deployments'))
    )
    op.create_index(op.f('ix_rule_deployments_backend'), 'rule_deployments', ['backend'], unique=False)
    op.create_index(op.f('ix_rule_deployments_created_at'), 'rule_deployments', ['created_at'], unique=False)
    op.create_index(op.f('ix_rule_deployments_rule_id'), 'rule_deployments', ['rule_id'], unique=False)
    op.create_table('tool_executions',
    sa.Column('tool_name', sa.String(length=80), nullable=False),
    sa.Column('session_id', sa.String(length=36), nullable=True),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('invoked_by', sa.String(length=200), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('params', app.db.base.JSONBType(), nullable=False),
    sa.Column('result', app.db.base.JSONBType(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('dry_run', sa.Boolean(), nullable=False),
    sa.Column('approval_id', sa.String(length=36), nullable=True),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['approval_id'], ['approval_requests.id'], name=op.f('fk_tool_executions_approval_id_approval_requests'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_tool_executions_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['session_id'], ['agent_sessions.id'], name=op.f('fk_tool_executions_session_id_agent_sessions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tool_executions'))
    )
    op.create_index(op.f('ix_tool_executions_created_at'), 'tool_executions', ['created_at'], unique=False)
    op.create_index(op.f('ix_tool_executions_incident_id'), 'tool_executions', ['incident_id'], unique=False)
    op.create_index(op.f('ix_tool_executions_session_id'), 'tool_executions', ['session_id'], unique=False)
    op.create_index(op.f('ix_tool_executions_status'), 'tool_executions', ['status'], unique=False)
    op.create_index('ix_tool_executions_tool_created', 'tool_executions', ['tool_name', 'created_at'], unique=False)
    op.create_index(op.f('ix_tool_executions_tool_name'), 'tool_executions', ['tool_name'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_tool_executions_tool_name'), table_name='tool_executions')
    op.drop_index('ix_tool_executions_tool_created', table_name='tool_executions')
    op.drop_index(op.f('ix_tool_executions_status'), table_name='tool_executions')
    op.drop_index(op.f('ix_tool_executions_session_id'), table_name='tool_executions')
    op.drop_index(op.f('ix_tool_executions_incident_id'), table_name='tool_executions')
    op.drop_index(op.f('ix_tool_executions_created_at'), table_name='tool_executions')
    op.drop_table('tool_executions')
    op.drop_index(op.f('ix_rule_deployments_rule_id'), table_name='rule_deployments')
    op.drop_index(op.f('ix_rule_deployments_created_at'), table_name='rule_deployments')
    op.drop_index(op.f('ix_rule_deployments_backend'), table_name='rule_deployments')
    op.drop_table('rule_deployments')
    op.drop_index('ix_playbook_runs_status_created', table_name='playbook_runs')
    op.drop_index(op.f('ix_playbook_runs_status'), table_name='playbook_runs')
    op.drop_index(op.f('ix_playbook_runs_playbook_id'), table_name='playbook_runs')
    op.drop_index(op.f('ix_playbook_runs_incident_id'), table_name='playbook_runs')
    op.drop_index(op.f('ix_playbook_runs_created_at'), table_name='playbook_runs')
    op.drop_table('playbook_runs')
    op.drop_index(op.f('ix_approval_requests_status'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_session_id'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_created_at'), table_name='approval_requests')
    op.drop_table('approval_requests')
    op.drop_index('ix_agent_messages_session_seq', table_name='agent_messages')
    op.drop_index(op.f('ix_agent_messages_session_id'), table_name='agent_messages')
    op.drop_index(op.f('ix_agent_messages_created_at'), table_name='agent_messages')
    op.drop_table('agent_messages')
    op.drop_index('ix_sigma_rules_tactic_severity', table_name='sigma_rules')
    op.drop_index(op.f('ix_sigma_rules_tactic'), table_name='sigma_rules')
    op.drop_index(op.f('ix_sigma_rules_status'), table_name='sigma_rules')
    op.drop_index(op.f('ix_sigma_rules_severity'), table_name='sigma_rules')
    op.drop_index(op.f('ix_sigma_rules_reference'), table_name='sigma_rules')
    op.drop_index(op.f('ix_sigma_rules_created_at'), table_name='sigma_rules')
    op.drop_table('sigma_rules')
    op.drop_index('ix_knowledge_chunks_source_category', table_name='knowledge_chunks')
    op.drop_index(op.f('ix_knowledge_chunks_source'), table_name='knowledge_chunks')
    op.drop_index(op.f('ix_knowledge_chunks_external_id'), table_name='knowledge_chunks')
    op.drop_index(op.f('ix_knowledge_chunks_document_id'), table_name='knowledge_chunks')
    op.drop_index(op.f('ix_knowledge_chunks_created_at'), table_name='knowledge_chunks')
    op.drop_index(op.f('ix_knowledge_chunks_category'), table_name='knowledge_chunks')
    op.drop_table('knowledge_chunks')
    op.drop_index(op.f('ix_incident_events_incident_id'), table_name='incident_events')
    op.drop_index(op.f('ix_incident_events_created_at'), table_name='incident_events')
    op.drop_table('incident_events')
    op.drop_index(op.f('ix_api_keys_key_prefix'), table_name='api_keys')
    op.drop_index(op.f('ix_api_keys_key_hash'), table_name='api_keys')
    op.drop_index(op.f('ix_api_keys_created_at'), table_name='api_keys')
    op.drop_table('api_keys')
    op.drop_index(op.f('ix_alerts_status'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_source'), table_name='alerts')
    op.drop_index('ix_alerts_severity_status', table_name='alerts')
    op.drop_index(op.f('ix_alerts_severity'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_risk_score'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_reference'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_incident_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_dedup_key'), table_name='alerts')
    op.drop_index('ix_alerts_dedup', table_name='alerts')
    op.drop_index(op.f('ix_alerts_created_at'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_asset'), table_name='alerts')
    op.drop_table('alerts')
    op.drop_index('ix_agent_sessions_status_created', table_name='agent_sessions')
    op.drop_index(op.f('ix_agent_sessions_status'), table_name='agent_sessions')
    op.drop_index(op.f('ix_agent_sessions_incident_id'), table_name='agent_sessions')
    op.drop_index(op.f('ix_agent_sessions_created_by'), table_name='agent_sessions')
    op.drop_index(op.f('ix_agent_sessions_created_at'), table_name='agent_sessions')
    op.drop_table('agent_sessions')
    op.drop_index(op.f('ix_workflow_runs_workflow_id'), table_name='workflow_runs')
    op.drop_index(op.f('ix_workflow_runs_status'), table_name='workflow_runs')
    op.drop_index(op.f('ix_workflow_runs_execution_id'), table_name='workflow_runs')
    op.drop_index(op.f('ix_workflow_runs_created_at'), table_name='workflow_runs')
    op.drop_table('workflow_runs')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_index(op.f('ix_users_created_at'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_threat_indicators_verdict'), table_name='threat_indicators')
    op.drop_index('ix_threat_indicators_value_type', table_name='threat_indicators')
    op.drop_index(op.f('ix_threat_indicators_value'), table_name='threat_indicators')
    op.drop_index(op.f('ix_threat_indicators_last_seen'), table_name='threat_indicators')
    op.drop_index(op.f('ix_threat_indicators_indicator_type'), table_name='threat_indicators')
    op.drop_index(op.f('ix_threat_indicators_created_at'), table_name='threat_indicators')
    op.drop_table('threat_indicators')
    op.drop_index(op.f('ix_settings_created_at'), table_name='settings')
    op.drop_table('settings')
    op.drop_index(op.f('ix_playbooks_slug'), table_name='playbooks')
    op.drop_index(op.f('ix_playbooks_created_at'), table_name='playbooks')
    op.drop_table('playbooks')
    op.drop_index(op.f('ix_knowledge_documents_source'), table_name='knowledge_documents')
    op.drop_index(op.f('ix_knowledge_documents_created_at'), table_name='knowledge_documents')
    op.drop_index(op.f('ix_knowledge_documents_content_hash'), table_name='knowledge_documents')
    op.drop_index(op.f('ix_knowledge_documents_category'), table_name='knowledge_documents')
    op.drop_table('knowledge_documents')
    op.drop_index(op.f('ix_integrations_slug'), table_name='integrations')
    op.drop_index(op.f('ix_integrations_health'), table_name='integrations')
    op.drop_index(op.f('ix_integrations_created_at'), table_name='integrations')
    op.drop_index(op.f('ix_integrations_category'), table_name='integrations')
    op.drop_table('integrations')
    op.drop_index(op.f('ix_incidents_status'), table_name='incidents')
    op.drop_index('ix_incidents_severity_status', table_name='incidents')
    op.drop_index(op.f('ix_incidents_severity'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_reference'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_owner'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_created_at'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_asset'), table_name='incidents')
    op.drop_table('incidents')
    op.drop_index(op.f('ix_cloud_findings_status'), table_name='cloud_findings')
    op.drop_index(op.f('ix_cloud_findings_severity'), table_name='cloud_findings')
    op.drop_index('ix_cloud_findings_service_severity', table_name='cloud_findings')
    op.drop_index(op.f('ix_cloud_findings_service'), table_name='cloud_findings')
    op.drop_index(op.f('ix_cloud_findings_region'), table_name='cloud_findings')
    op.drop_index(op.f('ix_cloud_findings_external_id'), table_name='cloud_findings')
    op.drop_index(op.f('ix_cloud_findings_created_at'), table_name='cloud_findings')
    op.drop_index(op.f('ix_cloud_findings_account_id'), table_name='cloud_findings')
    op.drop_table('cloud_findings')
    op.drop_index(op.f('ix_audit_logs_resource_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_request_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_created_at'), table_name='audit_logs')
    op.drop_index('ix_audit_logs_actor_created', table_name='audit_logs')
    op.drop_index('ix_audit_logs_action_created', table_name='audit_logs')
    op.drop_table('audit_logs')
