"""empty message

Revision ID: 652aa5cb31c9
Revises: 
Create Date: 2024-11-13 16:01:17.697151

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '652aa5cb31c9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('organizations',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('documents',
    sa.Column('document_handle', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('create_date', sa.DateTime(timezone=True), nullable=False),
    sa.Column('creator', sa.String(), nullable=False),
    sa.Column('file_handle', sa.String(), nullable=False),
    sa.Column('deleter', sa.String(), nullable=True),
    sa.Column('org_id', sa.UUID(), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('document_handle')
    )
    op.create_table('subjects',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('username', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('pub_key', sa.String(), nullable=False),
    sa.Column('org_id', sa.UUID(), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('subjects')
    op.drop_table('documents')
    op.drop_table('organizations')
    # ### end Alembic commands ###
