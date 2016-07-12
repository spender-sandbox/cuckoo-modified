#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import hashlib
import json
import logging
import os
import sys
import tempfile
import threading
import time
from datetime import datetime
from itertools import combinations

import zipfile
import StringIO
from bson.json_util import loads

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import store_temp_file
from lib.cuckoo.core.database import Database, TASK_COMPLETED, TASK_REPORTED, TASK_RUNNING, TASK_PENDING

# ElasticSearch not included, as it not officially maintained
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, InvalidDocument
    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False

# we need original db to reserve ID in db,
# to store later report, from master or slave
cuckoo_conf = Config("cuckoo")
reporting_conf = Config("reporting")

INTERVAL = 10
MINIMUMQUEUE = 5
RESET_LASTCHECK = 100

def required(package):
    sys.exit("The %s package is required: pip install %s" %
             (package, package))

try:
    from flask import Flask, request, make_response
except ImportError:
    required("flask")

try:
    import requests
except ImportError:
    required("requests")

try:
    from flask_restful import abort, reqparse
    from flask_restful import Api as RestApi, Resource as RestResource
except ImportError:
    required("flask-restful")

try:
    from sqlalchemy import DateTime
    from sqlalchemy import or_, and_
except ImportError:
    required("sqlalchemy")

try:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy(session_options=dict(autoflush=True))
except ImportError:
    required("flask-sqlalchemy")


def sha256(path):
    """Returns the SHA256 hash for a file."""
    f = open(path, "rb")
    h = hashlib.sha256()
    while True:
        buf = f.read(1024 * 1024)
        if not buf:
            break

        h.update(buf)
    return h.hexdigest()


class StringList(db.TypeDecorator):
    """List of comma-separated strings as field."""
    impl = db.Text

    def process_bind_param(self, value, dialect):
        return ", ".join(value)

    def process_result_value(self, value, dialect):
        return value.split(", ")


class Node(db.Model):
    """Cuckoo node database model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    url = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    last_check = db.Column(db.DateTime(timezone=False))
    machines = db.relationship("Machine", backref="node", lazy="dynamic")

    def __init__(self, name, url, enabled=True):
        self.name = name
        self.url = url
        self.enabled = enabled

    def list_machines(self):
        try:
            r = requests.get(os.path.join(self.url, "machines", "list"))

            for machine in r.json()["machines"]:
                yield Machine(name=machine["name"],
                              platform=machine["platform"],
                              tags=machine["tags"])
        except Exception as e:
            abort(404,
                  message="Invalid Cuckoo node (%s): %s" % (self.name, e))

    def status(self):
        try:
            r = requests.get(os.path.join(self.url, "cuckoo", "status"))
            return r.json()["tasks"]
        except Exception as e:
            log.critical("Possible invalid Cuckoo node (%s): %s",
                         self.name, e)

        return {}

    def submit_task(self, task):
        try:
            url = os.path.join(self.url, "tasks", "create", "file")

            # Remove the earlier appended comma
            if task.tags:
                if task.tags[-1] == ',': task.tags = task.tags[:-1]

            data = dict(
                package=task.package, timeout=task.timeout,
                priority=task.priority, options=task.options,
                machine=task.machine, platform=task.platform,
                tags=task.tags, custom=task.custom,
                memory=task.memory, clock=task.clock,
                enforce_timeout=task.enforce_timeout,
            )
            # If the file does not exist anymore, ignore it and move on
            # to the next file.
            if not os.path.isfile(task.path):
                task.finished = True
                db.session.commit()
                db.session.refresh(task)
                return

            files = dict(file=open(task.path, "rb"))
            r = requests.post(url, data=data, files=files)
            task.node_id = self.id

            # task.task_ids <- see how to loop it and store all ids,
            # because by default it nto saving it,
            # or saving as list which trigger errors
            task.task_id = r.json()["task_ids"][0]

            if task.main_task_id:
                main_db.set_status(task.main_task_id, TASK_RUNNING)
            # we don't need create extra id in master
            # reserving id in main db, to later store in mongo with the same id
            elif self.name != "master":
                main_task_id = main_db.add_path(
                    file_path=task.path,
                    package=task.package,
                    timeout=task.timeout,
                    options=task.options,
                    priority=task.priority,
                    machine=task.machine,
                    custom=task.custom,
                    memory=task.memory,
                    enforce_timeout=task.enforce_timeout,
                    tags=task.tags
                )
                main_db.set_status(main_task_id, TASK_RUNNING)
                task.main_task_id = main_task_id
            else:
                task.main_task_id = task.task_id

            # We have to refresh() the task object because otherwise we get
            # the unmodified object back in further sql queries..
            # TODO Commit once, refresh() all at once. This could potentially
            # become a bottleneck.
            db.session.commit()
            db.session.refresh(task)
        except Exception as e:
            log.critical("Error submitting task (task #%d, node %s): %s",
                         task.id, self.name, e)

    def fetch_tasks(self, status, since=None):
        try:
            url = os.path.join(self.url, "tasks", "list")
            params = dict(status=status)#completed_after=since,
            r = requests.get(url, params=params)
            return r.json()["tasks"]
        except Exception as e:
            log.critical("Error listing completed tasks (node %s): %s",
                         self.name, e)

        return []

    def get_report(self, task_id, fmt, stream=False):
        try:
            url = os.path.join(self.url, "tasks", "report",
                               "%d" % task_id, fmt)
            return requests.get(url, stream=stream)
        except Exception as e:
            log.critical("Error fetching report (task #%d, node %s): %s",
                         task_id, self.url, e)

    def delete_task(self, task_id):
        try:
            url = os.path.join(self.url, "tasks", "delete", "%d" % task_id)
            return requests.get(url).status_code == 200
        except Exception as e:
            log.critical("Error deleting task (task #%d, node %s): %s",
                         task_id, self.name, e)


class Machine(db.Model):
    """Machine database model related to a Cuckoo node."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    platform = db.Column(db.Text, nullable=False)
    tags = db.Column(StringList)
    node_id = db.Column(db.Integer, db.ForeignKey("node.id"))

    def __init__(self, name, platform, tags):
        self.name = name
        self.platform = platform
        self.tags = tags


class Task(db.Model):
    """Analysis task database model."""
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.Text)
    package = db.Column(db.Text)
    timeout = db.Column(db.Integer)
    priority = db.Column(db.Integer)
    options = db.Column(db.Text)
    machine = db.Column(db.Text)
    platform = db.Column(db.Text)
    tags = db.Column(db.Text)
    custom = db.Column(db.Text)
    memory = db.Column(db.Text)
    clock = db.Column(DateTime(timezone=False),
                   default=datetime.now(),
                   nullable=False)
    enforce_timeout = db.Column(db.Text)

    # Cuckoo node and Task ID this has been submitted to.
    node_id = db.Column(db.Integer, db.ForeignKey("node.id"))
    task_id = db.Column(db.Integer)
    finished = db.Column(db.Boolean, nullable=False)
    main_task_id = db.Column(db.Integer)

    def __init__(self, path, package, timeout, priority, options, machine,
                 platform, tags, custom, memory, clock, enforce_timeout, main_task_id=None):
        self.path = path
        self.package = package
        self.timeout = timeout
        self.priority = priority
        self.options = options
        self.machine = machine
        self.platform = platform
        self.tags = tags
        self.custom = custom
        self.memory = memory
        self.clock = clock
        self.enforce_timeout = enforce_timeout
        self.node_id = None
        self.task_id = None
        self.main_task_id = main_task_id
        self.finished = False


class StatusThread(threading.Thread):
    def submit_tasks(self, node):
        # Get tasks from main_db submitted through web interface
        for t in main_db.list_tasks(status=TASK_PENDING):
            if not Task.query.filter_by(main_task_id=t.id).all():
                # Convert array of tags into comma separated list
                tags = ','.join([tag.name for tag in t.tags])
                # Append a comma, to make LIKE searches more precise
                if tags: tags += ','
                args = dict( package=t.package, timeout=t.timeout, priority=t.priority,
                             options=t.options, machine=t.machine, platform=t.platform,
                             tags=tags, custom=t.custom, memory=t.memory, clock=t.clock,
                             enforce_timeout=t.enforce_timeout, main_task_id=t.id )
                task = Task(path=t.target, **args)
                db.session.add(task)

        db.session.commit()

        # Only get tasks that have not been pushed yet.
        q = Task.query.filter_by(node_id=None, finished=False)

        # Order by task priority and task id.
        q = q.order_by(-Task.priority, -Task.id)

        # Get available node tags
        machines = Machine.query.filter_by(node_id=node.id).all()

        # Get available tag combinations
        ta = set()
        for m in machines:
            for i in xrange(1, len(m.tags)+1):
                for t in combinations(m.tags, i):
                    ta.add(','.join(t))
        ta = list(ta)

        # Create filter query from tasks in ta
        tags = [ getattr(Task, "tags")=="" ]
        for t in ta:
            if len(t.split(',')) == 1:
                tags.append(getattr(Task, "tags")==(t+','))
            else:
                t = t.split(',')
                # ie. LIKE '%,%,%,'
                t_combined = [ getattr(Task, "tags").like("%s" % ('%,'*len(t)) ) ]
                for tag in t:
                    t_combined.append(getattr(Task, "tags").like("%%%s%%" % (tag+',') ))
                tags.append( and_(*t_combined) )

        # Filter by available tags
        q = q.filter(or_(*tags))

        # Submit appropriate tasks to node
        for task in q.limit(MINIMUMQUEUE).all():
            node.submit_task(task)

    def do_mongo(self, mongo_report, behaviour_report, mongo_db, t, node):

        if "processes" in behaviour_report:

            new_processes = []

            for process in behaviour_report.get("processes", []):
                new_process = dict(process)

                chunk = []
                chunks_ids = []
                # Loop on each process call.
                for index, call in enumerate(process["calls"]):
                    # If the chunk size is 100 or if the loop is completed then
                    # store the chunk in MongoDB.
                    if len(chunk) == 100:
                        to_insert = {"pid": process["process_id"],
                                     "calls": chunk}
                        chunk_id = mongo_db.calls.insert(to_insert)
                        chunks_ids.append(chunk_id)
                        # Reset the chunk.
                        chunk = []

                    # Append call to the chunk.
                    chunk.append(call)

                # Store leftovers.
                if chunk:
                    to_insert = {"pid": process["process_id"], "calls": chunk}
                    chunk_id = mongo_db.calls.insert(to_insert)
                    chunks_ids.append(chunk_id)

                # Add list of chunks.
                new_process["calls"] = chunks_ids
                new_processes.append(new_process)

            # Store the results in the report.
            mongo_report["behavior"] = dict(behaviour_report)
            mongo_report["behavior"]["processes"] = new_processes

        #patch info.id to have the same id as in main db
        mongo_report["info"]["id"] = t.main_task_id
        # add url to original analysis
        original_url = os.path.join(node.url.replace(str(reporting_conf.distributed.slave_api_port), str(reporting_conf.distributed.master_webgui_port)),
                                    "analysis", str(t.task_id))
        mongo_report.setdefault("original_url", original_url)
        mongo_db.analysis.save(mongo_report)

        # set complated_on time
        main_db.set_status(t.main_task_id, TASK_COMPLETED)
        # set reported time
        main_db.set_status(t.main_task_id, TASK_REPORTED)

    def fetch_latest_reports(self, node, last_check):

        finished = False

        # Fetch the latest reports.
        for task in node.fetch_tasks("reported", since=last_check):
            q = Task.query.filter_by(node_id=node.id, task_id=task["id"], finished=False)
            t = q.first()

            if t is None:
                continue

            # Update the last_check value of the Node for the next iteration.
            completed_on = datetime.strptime(task["completed_on"],
                                             "%Y-%m-%d %H:%M:%S")
            if not node.last_check or completed_on > node.last_check:
                node.last_check = completed_on

            # we already have reports on master
            # so we don't need duplicate work
            if node.name != "master":

                # Fetch each requested report.
                report = node.get_report(t.task_id, "distributed",
                                             stream=True)
                if report is None or report.status_code != 200:
                    log.debug("Error fetching %s report for task #%d",
                                "distributed", t.task_id)
                    continue

                temp_f = ''
                for chunk in report.iter_content(chunk_size=1024*1024):
                    temp_f += chunk

                report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "{}".format(t.main_task_id))
                if not os.path.isdir(report_path):
                    os.makedirs(report_path)

                if temp_f:
                    # will be stored to mongo db only
                    # we don't need it as file
                    if HAVE_MONGO:
                        if True:#try:
                            fileobj = StringIO.StringIO(temp_f)
                            file = zipfile.ZipFile(fileobj, "r")
                            for name in file.namelist():
                                if name.startswith("shots") or name == "reports/report.json":
                                    correct_dir = name.split(os.sep)[0]
                                    if not os.path.exists(os.path.join(report_path, correct_dir)):
                                        os.makedirs(os.path.join(report_path, correct_dir))
                                    try:
                                        unziped_file = open(os.path.join(report_path, name), "wb")
                                        unziped_file.write(file.read(name))
                                        unziped_file.close()
                                    except Exception as e:
                                        log.info(e)

                            if reporting_conf.mongodb.enabled:
                                    conn = MongoClient(reporting_conf.mongodb.host, reporting_conf.mongodb.port)
                                    mongo_db = conn[reporting_conf.mongodb.db]
                                    report = ""
                                    behaviour = ""
                                    if "report.mongo" in file.namelist():
                                        report = file.read("report.mongo")
                                        report = loads(report)
                                    if "behavior.report" in file.namelist():
                                        behaviour = file.read("behavior.report")
                                        behaviour = loads(behaviour)
                                    self.do_mongo(report, behaviour, mongo_db, t, node)
                                    finished = True
                                    conn.close()

                        #except Exception as e:
                        #    log.info(e)

                        del temp_f

            if finished:
                t.finished = True
                db.session.commit()
                db.session.refresh(t)

                # Delete the task and all its associated files.
                # (It will still remain in the nodes' database, though.)
                if reporting_conf.distributed.remove_task_on_slave:
                    node.delete_task(t.task_id)


    def run(self):
        global main_db
        global STATUSES
        while RUNNING:
            with app.app_context():
                start = datetime.now()
                statuses = {}

                # Request a status update on all Cuckoo nodes.
                for node in Node.query.filter_by(enabled=True).all():
                    status = node.status()
                    if not status:
                        continue

                    log.debug("Status.. %s -> %s", node.name, status)

                    statuses[node.name] = status

                    if status["pending"] < MINIMUMQUEUE:
                        self.submit_tasks(node)

                    if node.last_check:
                        last_check = int(node.last_check.strftime("%s"))
                    else:
                        last_check = 0

                    self.fetch_latest_reports(node, last_check)

                    # We just fetched all the "latest" tasks. However, it is
                    # for some reason possible that some reports are never
                    # fetched, and therefore we reset the "last_check"
                    # parameter when more than 10 tasks have not been fetched,
                    # thus preventing running out of diskspace.
                    status = node.status()
                    if status and status["reported"] > RESET_LASTCHECK:
                        node.last_check = None

                    # The last_check field of each node object has been
                    # updated as well as the finished field for each task that
                    # has been completed.
                    db.session.commit()
                    db.session.refresh(node)

                # Dump the uptime.
                if app.config["UPTIME_LOGFILE"] is not None:
                    with open(app.config["UPTIME_LOGFILE"], "ab") as f:
                        t = int(start.strftime("%s"))
                        c = json.dumps(dict(timestamp=t, status=statuses))
                        print>>f, c

                STATUSES = statuses

                # Sleep until roughly half a minute (configurable through
                # INTERVAL) has gone by.
                diff = (datetime.now() - start).seconds
                if diff < INTERVAL:
                    time.sleep(INTERVAL - diff)


class NodeBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("name", type=str)
        self._parser.add_argument("url", type=str)


class NodeRootApi(NodeBaseApi):
    def get(self):
        nodes = {}
        for node in Node.query.all():
            machines = []
            for machine in node.machines.all():
                machines.append(dict(
                    name=machine.name,
                    platform=machine.platform,
                    tags=machine.tags,
                ))

            nodes[node.name] = dict(
                name=node.name,
                url=node.url,
                machines=machines,
            )
        return dict(nodes=nodes)

    def post(self):
        args = self._parser.parse_args()
        node = Node(name=args["name"], url=args["url"])

        machines = []
        for machine in node.list_machines():
            machines.append(dict(
                name=machine.name,
                platform=machine.platform,
                tags=machine.tags,
            ))
            node.machines.append(machine)
            db.session.add(machine)

        db.session.add(node)
        db.session.commit()
        return dict(name=node.name, machines=machines)


class NodeApi(NodeBaseApi):
    def get(self, name):
        node = Node.query.filter_by(name=name).first()
        return dict(name=node.name, url=node.url)

    def put(self, name):
        args = self._parser.parse_args()
        node = Node.query.filter_by(name=name)
        node.name = args["name"]
        node.url = args["url"]
        db.session.commit()

    def delete(self, name):
        node = Node.query.filter_by(name=name).first()
        node.enabled = False
        db.session.commit()


class TaskBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("package", type=str)
        self._parser.add_argument("timeout", type=int)
        self._parser.add_argument("priority", type=int, default=1)
        self._parser.add_argument("options", type=str, default="")
        self._parser.add_argument("machine", type=str)
        self._parser.add_argument("platform", type=str, default="windows")
        self._parser.add_argument("tags", type=str, default="")
        self._parser.add_argument("custom", type=str)
        self._parser.add_argument("memory", type=str)
        self._parser.add_argument("clock", type=int)
        self._parser.add_argument("enforce_timeout", type=bool)


class TaskApi(TaskBaseApi):
    def get(self, task_id):
        task = Task.query.get(task_id)
        if task is None:
            abort(404, message="Task not found")

        return dict(tasks={task.id: dict(
            task_id=task.id, path=task.path, package=task.package,
            timeout=task.timeout, priority=task.priority,
            options=task.options, machine=task.machine,
            platform=task.platform, tags=task.tags,
            custom=task.custom, memory=task.memory,
            clock=task.clock, enforce_timeout=task.enforce_timeout
        )})

    def delete(self, task_id):
        task = Task.query.get(task_id)
        if task is None:
            abort(404, "Task not found")

        # Remove the sample related to this task.
        if os.path.isfile(task.path):
            os.unlink(task.path)

        # TODO Don't delete the task, but instead change its state to deleted.
        db.session.delete(task)
        db.session.commit()


class TaskRootApi(TaskBaseApi):
    def get(self):
        offset = request.args.get("offset")
        limit = request.args.get("limit")
        finished = request.args.get("finished")

        q = Task.query

        if finished is not None:
            q = q.filter_by(finished=int(finished))

        if offset is not None:
            q = q.offset(int(offset))

        if limit is not None:
            q = q.limit(int(limit))

        tasks = q.all()

        ret = {}

        for task in tasks:
            ret[task.id] = dict(
                id=task.id, path=task.path, package=task.package,
                timeout=task.timeout, priority=task.priority,
                options=task.options, machine=task.machine,
                platform=task.platform, tags=task.tags,
                custom=task.custom, memory=task.memory,
                clock=task.clock, enforce_timeout=task.enforce_timeout,
                task_id=task.task_id, node_id=task.node_id,
            )
        log.info(ret)
        return dict(tasks=ret)

    def post(self):
        args = self._parser.parse_args()
        f = request.files["file"]

        path = store_temp_file(f.read(), f.filename, path=app.config["SAMPLES_DIRECTORY"])

        main_task_id = main_db.demux_sample_and_add_to_db(file_path=path, **args)

        if main_task_id: args["main_task_id"] = main_task_id[0]
        task = Task(path=path, **args)
        db.session.add(task)
        db.session.commit()

        return dict(task_id=task.id)

class ReportingBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

    def get_node_url(self, node_id):

        node = Node.query.filter_by(id = node_id)
        node = node.first()

        if not node:
            abort(404, message="Node not found")

        return node.url


class IocApi(ReportingBaseApi):

    def get(self, task_id):
        task = Task.query.get(task_id)
        url = self.get_node_url(task.node_id)
        res = self.get_iocs(url, task.main_task_id)

        if res and res.status_code == 200:
            return res.json()
        else:
            abort(404, message="Iocs report not found")

    def get_iocs(self, url, task_id, stream=False):
        try:
            url = os.path.join(url, "tasks", "iocs",
                               "%d" % task_id)
            return requests.get(url, stream=stream)
        except Exception as e:
            log.critical("Error fetching report (task #%d, node %s): %s",
                         task_id, self.url, e)



class ReportApi(ReportingBaseApi):

    report_formats = {
        "distributed": "distributed",
    }

    def get(self, task_id, report="json"):
        task = Task.query.get(task_id)
        url = self.get_node_url(task.node_id)

        if not task:
            abort(404, message="Task not found")

        if not task.finished:
            abort(404, message="Task not finished yet")

        if self.report_formats[report]:
            res = self.get_report(url, task.main_task_id, report)
            if res and res.status_code == 200:
                return res.json()
            else:
                abort(404, message="Report format not found")

        abort(404, message="Invalid report format")

    def get_report(self, url, task_id, fmt, stream=False):
        try:
            url = os.path.join(url, "tasks", "report",
                               "%d" % task_id, fmt)
            return requests.get(url, stream=stream)
        except Exception as e:
            log.critical("Error fetching report (task #%d, node %s): %s",
                         task_id, self.url, e)


class StatusRootApi(RestResource):
    def get(self):
        null = None

        tasks = Task.query.filter(Task.node_id != null)

        tasks = dict(
            processing=tasks.filter_by(finished=False).count(),
            processed=tasks.filter_by(finished=True).count(),
            pending=Task.query.filter_by(node_id=None).count(),
        )
        return dict(nodes=STATUSES, tasks=tasks)


def output_json(data, code, headers=None):
    resp = make_response(json.dumps(data), code)
    resp.headers.extend(headers or {})
    return resp

def output_xml(data, code, headers=None):
    resp = make_response(data, code)
    resp.headers.extend(headers or {})
    return resp

class DistRestApi(RestApi):
    def __init__(self, *args, **kwargs):
        RestApi.__init__(self, *args, **kwargs)
        self.representations = {
            #"application/xml": output_xml,
            "application/json": output_json,
        }


def create_app(database_connection):
    app = Flask("Distributed Cuckoo")
    app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config["SECRET_KEY"] = os.urandom(32)

    restapi = DistRestApi(app)
    restapi.add_resource(NodeRootApi, "/node")
    restapi.add_resource(NodeApi, "/node/<string:name>")
    restapi.add_resource(TaskRootApi, "/task")
    restapi.add_resource(TaskApi, "/task/<int:task_id>")
    restapi.add_resource(ReportApi,
                         "/report/<int:task_id>",
                         "/report/<int:task_id>/<string:report>")
    restapi.add_resource(IocApi,
                         "/iocs/<int:task_id>")
    restapi.add_resource(StatusRootApi, "/status")

    db.init_app(app)

    with app.app_context():
        db.create_all()

    return app

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="0.0.0.0", help="Host to listen on")
    p.add_argument("port", nargs="?", type=int, default=9003, help="Port to listen on")
    p.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--db", type=str, default="sqlite:///dist.db", help="Database connection string")
    p.add_argument("--samples-directory", type=str, required=True, help="Samples directory")
    p.add_argument("--uptime-logfile", type=str, help="Uptime logfile path")
    args = p.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    log = logging.getLogger("cuckoo.distributed")

    if not os.path.isdir(args.samples_directory):
        os.makedirs(args.samples_directory)

    RUNNING, STATUSES = True, {}
    main_db = Database()

    app = create_app(database_connection=args.db)
    app.config["SAMPLES_DIRECTORY"] = args.samples_directory
    app.config["UPTIME_LOGFILE"] = args.uptime_logfile

    t = StatusThread()
    t.daemon = True
    t.start()

    app.run(host=args.host, port=args.port)

