# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Add shrike and Parent ID Columns

Revision ID: f111620bb8
Revises: 4b09c454108c
Create Date: 2015-03-29 08:43:11.468664

"""
# revision identifiers, used by Alembic.
revision = 'f111620bb8'
down_revision = '4b09c454108c'

from alembic import op
import sqlalchemy as sa

import os.path
import sqlalchemy as sa
import sys
from datetime import datetime

try:
    from dateutil.parser import parse
except ImportError:
    print "Unable to import dateutil.parser",
    print "(install with `pip install python-dateutil`)"
    sys.exit()

try:
    from alembic import op
except ImportError:
    print "Unable to import alembic (install with `pip install alembic`)"
    sys.exit()

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(curdir, "..", ".."))

import lib.cuckoo.core.database as db

def _perform(upgrade):
    conn = op.get_bind()

    # Read data.
    tasks_data = []
    old_tasks = conn.execute("select id, target, category, timeout, priority, custom, machine, package, options, platform, memory, enforce_timeout, clock, added_on, started_on, completed_on, status, sample_id, dropped_files, running_processes, api_calls, domains, signatures_total, signatures_alert, files_written, registry_keys_modified, crash_issues, anti_issues, analysis_started_on, analysis_finished_on, processing_started_on, processing_finished_on, signatures_started_on, signatures_finished_on, reporting_started_on, reporting_finished_on, timedout, machine_id from tasks").fetchall()

    for item in old_tasks:
        d = {}
        d["id"] = item[0]
        d["target"] = item[1]
        d["category"] = item[2]
        d["timeout"] = item[3]
        d["priority"] = item[4]
        d["custom"] = item[5]
        d["machine"] = item[6]
        d["package"] = item[7]
        d["options"] = item[8]
        d["platform"] = item[9]
        d["memory"] = item[10]
        d["enforce_timeout"] = item[11]

        if isinstance(item[12], datetime):
            d["clock"] = item[12]
        elif item[12]:
            d["clock"] = parse(item[12])
        else:
            d["clock"] = None

        if isinstance(item[13], datetime):
            d["added_on"] = item[13]
        elif item[13]:
            d["added_on"] = parse(item[13])
        else:
            d["added_on"] = None

        if isinstance(item[14], datetime):
            d["started_on"] = item[14]
        elif item[14]:
            d["started_on"] = parse(item[14])
        else:
            d["started_on"] = None

        if isinstance(item[15], datetime):
            d["completed_on"] = item[15]
        elif item[15]:
            d["completed_on"] = parse(item[15])
        else:
            d["completed_on"] = None

        d["status"] = item[16]
        d["sample_id"] = item[17]
        d["dropped_files"] = item[18]
        d["running_processes"] = item[19]
        d["api_calls"] = item[20]
        d["domains"] = item[21]
        d["signatures_total"] = item[22]
        d["signatures_alert"] = item[23]
        d["files_written"] = item[24]
        d["registry_keys_modified"] = item[25] 
        d["crash_issues"] = item[26]
        d["anti_issues"] = item[27]
        d["analysis_started_on"] = item[28]
        d["analysis_finished_on"] = item[29]
        d["processing_started_on"] = item[30]
        d["processing_finished_on"] = item[31]
        d["signatures_started_on"] = item[32]
        d["signatures_finished_on"] = item[33]
        d["reporting_started_on"] = item[34]
        d["reporting_finished_on"] = item[35]

        d["timedout"] = item[36]
        d["machine_id"] = item[37]


        if upgrade:
            # Columns for statistics (via Thorsten's statistics page)
            d["shrike_url"] = None
            d["shrike_refer"] = None
            d["shrike_msg"] = None
            d["shrike_sid"] = None

            d["parent_id"] = None
        tasks_data.append(d)

    if conn.engine.driver == "mysqldb":
        # Disable foreign key checking to migrate table avoiding checks.
        op.execute('SET foreign_key_checks = 0')

    # Drop old table.
    op.drop_table("tasks")

    # Create table with 1.2 schema.
    if upgrade:
        op.create_table(
            "tasks",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("category", sa.String(length=255), nullable=False),
            sa.Column("timeout", sa.Integer(), server_default="0", nullable=False),
            sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
            sa.Column("custom", sa.String(length=255), nullable=True),
            sa.Column("machine", sa.String(length=255), nullable=True),
            sa.Column("package", sa.String(length=255), nullable=True),
            sa.Column("options", sa.String(length=255), nullable=True),
            sa.Column("platform", sa.String(length=255), nullable=True),
            sa.Column("memory", sa.Boolean(), nullable=False, default=False),
            sa.Column("enforce_timeout", sa.Boolean(), nullable=False, default=False),
            sa.Column("clock", sa.DateTime(timezone=False), default=datetime.now, nullable=False),
            sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
            sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("status", sa.Enum("pending", "running", "completed", "reported", "recovered", "failed_analysis", "failed_processing", "failed_reporting", name="status_type"), server_default="pending", nullable=False),
            sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),

            sa.Column("dropped_files", sa.Integer(), nullable=True),
            sa.Column("running_processes", sa.Integer(), nullable=True),
            sa.Column("api_calls", sa.Integer(), nullable=True),
            sa.Column("domains", sa.Integer(), nullable=True),
            sa.Column("signatures_total", sa.Integer(), nullable=True),
            sa.Column("signatures_alert", sa.Integer(), nullable=True),
            sa.Column("files_written", sa.Integer(), nullable=True),
            sa.Column("registry_keys_modified", sa.Integer(), nullable=True),
            sa.Column("crash_issues", sa.Integer(), nullable=True),
            sa.Column("anti_issues", sa.Integer(), nullable=True),
            sa.Column("analysis_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("analysis_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("processing_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("processing_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("signatures_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("signatures_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("reporting_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("reporting_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("timedout", sa.Boolean(), nullable=False, default=False),
            sa.Column("machine_id", sa.Integer(), nullable=True),

            sa.Column("shrike_url", sa.String(length=4096), nullable=True),
            sa.Column("shrike_refer", sa.String(length=4096), nullable=True),
            sa.Column("shrike_msg", sa.String(length=4096), nullable=True),
            sa.Column("shrike_sid", sa.Integer(), nullable=True),

            sa.Column("parent_id", sa.Integer(), nullable=True),

            sa.PrimaryKeyConstraint("id")
        )
    else:
        op.create_table(
            "tasks",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("category", sa.String(length=255), nullable=False),
            sa.Column("timeout", sa.Integer(), server_default="0", nullable=False),
            sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
            sa.Column("custom", sa.String(length=255), nullable=True),
            sa.Column("machine", sa.String(length=255), nullable=True),
            sa.Column("package", sa.String(length=255), nullable=True),
            sa.Column("options", sa.String(length=255), nullable=True),
            sa.Column("platform", sa.String(length=255), nullable=True),
            sa.Column("memory", sa.Boolean(), nullable=False, default=False),
            sa.Column("enforce_timeout", sa.Boolean(), nullable=False, default=False),
            sa.Column("clock", sa.DateTime(timezone=False), default=datetime.now, nullable=False),
            sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
            sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("status", sa.Enum("pending", "running", "completed", "reported", "recovered", "failed_analysis", "failed_processing", "failed_reporting", name="status_type"), server_default="pending", nullable=False),
            sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),

            sa.Column("dropped_files", sa.Integer(), nullable=True),
            sa.Column("running_processes", sa.Integer(), nullable=True),
            sa.Column("api_calls", sa.Integer(), nullable=True),
            sa.Column("domains", sa.Integer(), nullable=True),
            sa.Column("signatures_total", sa.Integer(), nullable=True),
            sa.Column("signatures_alert", sa.Integer(), nullable=True),
            sa.Column("files_written", sa.Integer(), nullable=True),
            sa.Column("registry_keys_modified", sa.Integer(), nullable=True),
            sa.Column("crash_issues", sa.Integer(), nullable=True),
            sa.Column("anti_issues", sa.Integer(), nullable=True),
            sa.Column("analysis_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("analysis_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("processing_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("processing_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("signatures_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("signatures_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("reporting_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("reporting_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("timedout", sa.Boolean(), nullable=False, default=False),
            sa.Column("machine_id", sa.Integer(), nullable=True),

            sa.Column("shrike_url", sa.String(length=4096), nullable=True),
            sa.Column("shrike_refer", sa.String(length=4096), nullable=True),
            sa.Column("shrike_msg", sa.String(length=4096), nullable=True),
            sa.Column("shrike_sid", sa.Integer(), nullable=True),

            sa.Column("parent_id", sa.Integer(), nullable=True),

            sa.PrimaryKeyConstraint("id")
        )
    if conn.engine.driver == "mysqldb":
        op.execute('COMMIT')

    # Insert data.
    op.bulk_insert(db.Task.__table__, tasks_data)

    if conn.engine.driver == "mysqldb":
        # Enable foreign key.
        op.execute('SET foreign_key_checks = 1')

def upgrade():
    _perform(upgrade=True)

def downgrade():
    _perform(upgrade=False)
