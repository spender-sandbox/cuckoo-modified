# Copyright (C) 2010-2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import shutil

from collections import defaultdict
from datetime import datetime, timedelta

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.core.database import Database, Task

log = logging.getLogger(__name__)
cfg = Config("reporting")
db = Database()

# Global connections
if cfg.mongodb and cfg.mongodb.enabled:
    from gridfs import GridFS
    from pymongo import MongoClient
    host = cfg.mongodb.get("host", "127.0.0.1")
    port = cfg.mongodb.get("port", 27017)
    mdb = cfg.mongodb.get("db", "cuckoo")
    try:
        results_db = MongoClient(host, port)[mdb]
        fs = GridFS(results_db)
    except Exception as e:
        log.warning("Unable to connect to MongoDB: %s", str(e))

if cfg.elasticsearchdb and cfg.elasticsearchdb.enabled:
    from elasticsearch import Elasticsearch
    idx = cfg.elasticsearchdb.index + "-*"
    try:
        es = Elasticsearch(
                hosts = [{
                    "host": cfg.elasticsearchdb.host,
                    "port": cfg.elasticsearchdb.port,
                }],
                timeout = 60,
             )
    except Exception as e:
        log.warning("Unable to connect to ElasticSearch: %s", str(e))

def delete_mongo_data(curtask=None, tid=None):
    # TODO: Class-ify this or make it a function in utils, some code reuse
    # between this/process.py/django view
    analyses = results_db.analysis.find({"info.id": int(tid)})
    if analyses.count > 0:
        for analysis in analyses:
            if "file_id" in analysis["target"]:
                if results_db.analysis.find({"target.file_id": ObjectId(analysis["target"]["file_id"])}).count() == 1:
                    fs.delete(ObjectId(analysis["target"]["file_id"]))
            for shot in analysis["shots"]:
                if results_db.analysis.find({"shots": ObjectId(shot)}).count() == 1:
                    fs.delete(ObjectId(shot))
            if "pcap_id" in analysis["network"] and results_db.analysis.find({"network.pcap_id": ObjectId(analysis["network"]["pcap_id"])}).count() == 1:
                fs.delete(ObjectId(analysis["network"]["pcap_id"]))
            if "sorted_pcap_id" in analysis["network"] and results_db.analysis.find({"network.sorted_pcap_id": ObjectId(analysis["network"]["sorted_pcap_id"])}).count() == 1:
                fs.delete(ObjectId(analysis["network"]["sorted_pcap_id"]))
            for drop in analysis["dropped"]:
                if "object_id" in drop and results_db.analysis.find({"dropped.object_id": ObjectId(drop["object_id"])}).count() == 1:
                    fs.delete(ObjectId(drop["object_id"]))
            for process in analysis.get("behavior", {}).get("processes", []):
                for call in process["calls"]:
                    results_db.calls.remove({"_id": ObjectId(call)})
            results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})
        log.debug("Task #{0} deleting MongoDB data for Task #{1}".format(
                  curtask, tid))

def delete_elastic_data(curtask=None, tid=None):
    # TODO: Class-ify this or make it a function in utils, some code reuse
    # between this/process.py/django view
    analyses = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"{0}\"".format(task_id)
               )["hits"]["hits"]
    if len(analyses) > 0:
        for analysis in analyses:
            esidx = analysis["_index"]
            esid = analysis["_id"]
            if analysis["_source"]["behavior"]:
                for process in analysis["_source"]["behavior"]["processes"]:
                    for call in process["calls"]:
                        es.delete(
                            index=esidx,
                            doc_type="calls",
                            id=call,
                        )
            es.delete(
                index=esidx,
                doc_type="analysis",
                id=esid,
                )
        log.debug("Task #{0} deleting ElasticSearch data for Task #{1}".format(
                  curtask, tid))

def delete_directory(curtask=None, deldir=None):
    if os.path.isdir(deldir):
        try:
            shutil.rmtree(deldir)
            log.debug("Task #{0} deleting {1} due to retention quota".format(
                curtask, deldir))
        except (IOError, OSError) as e:
            log.warn("Error removing {0}: {1}".format(deldir, e))

def delete_file(curtask=None, delfile=None):
    if os.path.exists(delfile):
        try:
            os.remove(delfile)
            log.debug("Task #{0} deleting {1} due to retention quota".format(
                curtask, delfile))
        except OSError as e:
            log.warn("Error removing {0}: {1}".format(delfile, e))

class Retention(Report):
    """Used to manage data retention and delete task data from
    disk after they have become older than the configured values.
    """
    order = 10000

    def run(self, results):
        # Curtask used for logging when deleting files
        curtask = results["info"]["id"]
        # Retains the last Task ID checked for retention settings per category
        taskCheck = defaultdict(int)
        # Handle the case where someone doesn't restart cuckoo and issues
        # process.py manually, the directiry structure is created in the
        # startup of cuckoo.py
        retPath = os.path.join(CUCKOO_ROOT, "storage", "retention")
        if not os.path.isdir(retPath):
            log.warn("Retention log directory doesn't exist. Creating it now.")
            os.mkdir(retPath)
        else:
            try:
                taskFile = os.path.join(retPath, "task_check.log")
                with open(taskFile, "r") as taskLog:
                    taskCheck = json.loads(taskLog.read())
            except Exception as e:
                log.warn("Failed to load retention log, if this is not the "
                         "time running retention, review the error: {0}".format(
                         e))

        delLocations = {
            "memory": CUCKOO_ROOT + "/storage/analyses/{0}/memory.dmp",
            "procmemory": CUCKOO_ROOT + "/storage/analyses/{0}/memory",
            "pcap": CUCKOO_ROOT + "/storage/analyses/{0}/dump.pcap",
            "sortedpcap": CUCKOO_ROOT + "/storage/analyses/{0}/dump_sorted.pcap",
            "bsonlogs": CUCKOO_ROOT + "/storage/analyses/{0}/logs",
            "dropped": CUCKOO_ROOT + "/storage/analyses/{0}/files",
            "screencaps": CUCKOO_ROOT + "/storage/analyses/{0}/shots",
            "reports": CUCKOO_ROOT + "/storage/analyses/{0}/reports",
            "malheur": CUCKOO_ROOT + "/storage/malheur/reports/{0}.txt",
            # Handled seperately
            "mongo": None,
            "elastic": None,
        }
        retentions = self.options
        del retentions["enabled"]
        saveTaskLogged = dict()
        for item in retentions.keys():
            # We only want to query the database for tasks that we have
            # retentions set for.
            if self.options[item] == False:
                continue
            # Sanitation
            if taskCheck[item] == 0:
                lastTaskLogged = None
            else:
                lastTaskLogged = taskCheck[item]
            add_date = datetime.now() - timedelta(days=retentions[item])
            buf = db.list_tasks(added_before=add_date,
                                id_after=lastTaskLogged,
                                order_by=Task.id.asc())
            lastTask = 0
            if buf:
                # We need to delete some data
                for tid in buf:
                    lastTask = tid.to_dict()["id"]
                    if delLocations[item]:
                        delete = delLocations[item].format(lastTask)
                    if item == "memory":
                        delete_file(curtask=curtask, delfile=delete)
                    elif item == "procmemory":
                        delete_directory(curtask=curtask, deldir=delete)
                    elif item == "pcap":
                        delete_file(curtask=curtask, delfile=delete)
                    elif item == "sortedpcap":
                        delete_file(curtask=curtask, delfile=delete)
                    elif item == "bsonlogs":
                        delete_directory(curtask=curtask, deldir=delete)
                    elif item == "dropped":
                        delete_directory(curtask=curtask, deldir=delete)
                    elif item == "screencaps":
                        delete_directory(curtask=curtask, deldir=delete)
                    elif item == "reports":
                        delete_directory(curtask=curtask, deldir=delete)
                    elif item == "mongo":
                        if cfg.mongodb and cfg.mongodb.enabled:
                            delete_mongo_data(curtask=curtask, tid=lastTask)
                    elif item == "elastic":
                        if cfg.elasticsearchdb and cfg.elasticsearchdb.enabled:
                            delete_elastic_data(curtask=curtask, tid=lastTask)
                saveTaskLogged[item] = int(lastTask)
            else:
                saveTaskLogged[item] = 0

        # Write the task log for future reporting, to avoid returning tasks
        # that we have already deleted data from.
        with open(os.path.join(retPath, "task_check.log"), "w") as taskLog:
            taskLog.write(json.dumps(saveTaskLogged))
