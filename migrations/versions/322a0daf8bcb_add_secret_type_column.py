"""add secret_type column

Revision ID: 322a0daf8bcb
Revises:
Create Date: 2019-10-10 10:58:23.333613

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '322a0daf8bcb'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'implementation_secrets',
        sa.Column('secret_type', sa.String, server_default=''))
    op.execute('UPDATE implementation_secrets '
               'SET secret_type = "macaroon" WHERE implementation IS "lnd"')
    op.execute('UPDATE implementation_secrets '
               'SET secret_type = "password" WHERE implementation IS "eclair"')
    op.rename_table('implementation_secrets', 'tmp_table')
    op.create_table('implementation_secrets',
        sa.Column('implementation', sa.String, primary_key=True),
        sa.Column('secret_type', sa.String, primary_key=True),
        sa.Column('active', sa.Boolean),
        sa.Column('secret', sa.LargeBinary),
        sa.Column('scrypt_params', sa.LargeBinary))
    op.execute('INSERT INTO implementation_secrets SELECT implementation, '
               'secret_type, active, secret, scrypt_params FROM tmp_table')


def downgrade():
    print('Downgrade is not supported')
    import sys
    sys.exit(1)
