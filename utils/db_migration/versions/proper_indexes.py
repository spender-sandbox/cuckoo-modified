# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Proper indexing

Revision ID: 3c8bf4133b44
Revises: f111620bb8
Create Date: 2016-05-13 11:04:41.685468

"""

# revision identifiers, used by Alembic.
revision = '3c8bf4133b44'
down_revision = 'f111620bb8'

from alembic import op
import os.path
import sqlalchemy as sa
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(curdir, "..", ".."))

import lib.cuckoo.core.database as db

def upgrade():
    op.drop_index("hash_index", "samples")

    op.create_index("md5_index", "samples", ["md5"])
    op.create_index("sha1_index", "samples", ["sha1"])
    op.create_index("sha256_index", "samples", ["sha256"], unique=True)

    op.create_index("category_index", "tasks", ["category"])
    op.create_index("status_index", "tasks", ["status"])
    op.create_index("added_on_index", "tasks", ["added_on"])
    op.create_index("completed_on_index", "tasks", ["completed_on"])

def downgrade():
    op.drop_index("md5_index", "samples")
    op.drop_index("sha1_index", "samples")
    op.drop_index("sha256_index", "samples")

    op.drop_index("category_index", "tasks")
    op.drop_index("status_index", "tasks")
    op.drop_index("added_on_index", "tasks")
    op.drop_index("completed_on_index", "tasks")

    op.create_index("hash_index", "samples",
                    ["md5", "crc32", "sha1", "sha256", "sha512"],
                    unique=True)
