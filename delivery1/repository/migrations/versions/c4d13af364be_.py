"""empty message

Revision ID: c4d13af364be
Revises: 1859b77913ac
Create Date: 2024-11-19 18:29:30.802873

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4d13af364be'
down_revision = '1859b77913ac'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.alter_column('file_handle',
               existing_type=sa.VARCHAR(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.alter_column('file_handle',
               existing_type=sa.VARCHAR(),
               nullable=False)

    # ### end Alembic commands ###
