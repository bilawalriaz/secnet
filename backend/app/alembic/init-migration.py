"""Initial schema

Revision ID: 001
Revises: 
Create Date: 2023-02-24 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(), nullable=False, unique=True, index=True),
        sa.Column('full_name', sa.String(), nullable=True),
        sa.Column('role', sa.String(), nullable=False, server_default='user'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
    )
    
    # Create endpoint_groups table
    op.create_table(
        'endpoint_groups',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
    )
    
    # Create endpoints table
    op.create_table(
        'endpoints',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('address', sa.String(), nullable=False),
        sa.Column('type', sa.String(), nullable=False, server_default='ip'),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('group_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('endpoint_groups.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
    )
    
    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('parameters', postgresql.JSON(), nullable=True),
        sa.Column('scheduled_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='pending'),
    )
    
    # Create scan_targets table
    op.create_table(
        'scan_targets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('endpoint_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('endpoints.id'), nullable=False),
    )
    
    # Create scan_results table
    op.create_table(
        'scan_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('endpoint_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('endpoints.id'), nullable=False),
        sa.Column('raw_results', postgresql.JSON(), nullable=False),
        sa.Column('open_ports', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('vulnerabilities', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('os_detection', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    
    # Create scheduled_scans table
    op.create_table(
        'scheduled_scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('scan_config', postgresql.JSON(), nullable=False),
        sa.Column('schedule_type', sa.String(), nullable=False),
        sa.Column('cron_expression', sa.String(), nullable=True),
        sa.Column('next_run', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
    )
    
    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('key_hash', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
    )
    
    # Create indexes
    op.create_index('ix_endpoints_address', 'endpoints', ['address'])
    op.create_index('ix_endpoints_group_id', 'endpoints', ['group_id'])
    op.create_index('ix_scans_user_id', 'scans', ['user_id'])
    op.create_index('ix_scan_targets_scan_id', 'scan_targets', ['scan_id'])
    op.create_index('ix_scan_results_scan_id', 'scan_results', ['scan_id'])
    op.create_index('ix_scan_results_endpoint_id', 'scan_results', ['endpoint_id'])
    op.create_index('ix_scheduled_scans_user_id', 'scheduled_scans', ['user_id'])
    op.create_index('ix_api_keys_user_id', 'api_keys', ['user_id'])


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('api_keys')
    op.drop_table('scheduled_scans')
    op.drop_table('scan_results')
    op.drop_table('scan_targets')
    op.drop_table('scans')
    op.drop_table('endpoints')
    op.drop_table('endpoint_groups')
    op.drop_table('users')
