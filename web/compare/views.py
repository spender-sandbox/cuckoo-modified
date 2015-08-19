# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from django.conf import settings
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

sys.path.append(settings.CUCKOO_PATH)

import lib.cuckoo.common.compare as compare
from lib.cuckoo.common.config import Config

enabledconf = dict()
confdata = Config("reporting").get_config()
for item in confdata:
    if confdata[item]["enabled"] == "yes":
        enabledconf[item] = True
    else:
        enabledconf[item] = False

if enabledconf["mongodb"]:
    import pymongo
    results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]

if enabledconf["elasticsearchdb"]:
    from elasticsearch import Elasticsearch
    es = Elasticsearch(
             hosts = [{
                 "host": settings.ELASTIC_HOST,
                 "port": settings.ELASTIC_PORT,
             }],
             timeout = 60
         )

@require_safe
def left(request, left_id):
    if enabledconf["mongodb"]:
        left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if enabledconf["elasticsearchdb"]:
        hits = es.search(
                   index="cuckoo-*",
                   doc_type="analysis",
                   q="info.id: \"%s\"" % left_id
                )["hits"]["hits"]
        if hits:
            left = hits[-1]["_source"]
        else:
            left = None
    if not left:
        return render_to_response("error.html",
                                  {"error": "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))

    # Select all analyses with same file hash.
    if enabledconf["mongodb"]:
        records = results_db.analysis.find(
            {
                "$and": [
                    {"target.file.md5": left["target"]["file"]["md5"]},
                    {"info.id": {"$ne": int(left_id)}}
                ]
            },
            {"target": 1, "info": 1}
        )
    if enabledconf["elasticsearchdb"]:
        records = list()
        results = es.search(
                      index="cuckoo-*",
                      doc_type="analysis",
                      q="target.file.md5: \"%s\" NOT info.id: \"%s\"" % (
                            left["target"]["file"]["md5"], left_id)
                  )["hits"]["hits"]
        for item in results:
            records.append(item["_source"])

    return render_to_response("compare/left.html",
                              {"left": left, "records": records},
                              context_instance=RequestContext(request))

@require_safe
def hash(request, left_id, right_hash):
    if enabledconf["mongodb"]:
        left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if enabledconf["elasticsearchdb"]:
        hits = es.search(
                   index="cuckoo-*",
                   doc_type="analysis",
                   q="info.id: \"%s\"" % left_id
               )["hits"]["hits"]
        if hits:
            left = hits[-1]["_source"]
        else:
            left = None
    if not left:
        return render_to_response("error.html",
                                  {"error": "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))

    # Select all analyses with same file hash.
    if enabledconf["mongodb"]:
        records = results_db.analysis.find(
            {
                "$and": [
                    {"target.file.md5": left["target"]["file"]["md5"]},
                    {"info.id": {"$ne": int(left_id)}}
                ]
            },
            {"target": 1, "info": 1}
        )
    if enabledconf["elasticsearchdb"]:
        records = list()
        results = es.search(
                      index="cuckoo-*",
                      doc_type="analysis",
                      q="target.file.md5: \"%s\" NOT info.id: \"%s\"" % (
                            right_hash, left_id)
                  )["hits"]["hits"]
        for item in results:
            records.append(item["_source"])

    # Select all analyses with specified file hash.
    return render_to_response("compare/hash.html",
                              {"left": left, "records": records, "hash": right_hash},
                              context_instance=RequestContext(request))

@require_safe
def both(request, left_id, right_id):
    if enabledconf["mongodb"]:
        left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
        right = results_db.analysis.find_one({"info.id": int(right_id)}, {"target": 1, "info": 1})
        # Execute comparison.
        counts = compare.helper_percentages_mongo(results_db, left_id, right_id)
    if enabledconf["elasticsearchdb"]:
        left = es.search(
                   index="cuckoo-*",
                   doc_type="analysis",
                   q="info.id: \"%s\"" % left_id
               )["hits"]["hits"][-1]["_source"]
        right = es.search(
                    index="cuckoo-*",
                    doc_type="analysis",
                    q="info.id: \"%s\"" % right_id
                )["hits"]["hits"][-1]["_source"]
        counts = compare.helper_percentages_elastic(es, left_id, right_id)

    return render_to_response("compare/both.html",
                              {"left": left, "right": right, "left_counts": counts[left_id],
                               "right_counts": counts[right_id]},
                               context_instance=RequestContext(request))
