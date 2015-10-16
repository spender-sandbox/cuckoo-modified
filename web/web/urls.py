# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import patterns, include, url

urlpatterns = patterns("",
    url(r"^$", "dashboard.views.index"),
    url(r"^analysis/", include("analysis.urls")),
    url(r"^compare/", include("compare.urls")),
    url(r"^submit/", include("submission.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w+)/$", "analysis.views.mongo_file"),
    url(r"^file/(?P<category>\w+)/(?P<task_id>\d+)/(?P<dlfile>\w+)/$", "analysis.views.elastic_file"),
    url(r"^filereport/(?P<task_id>\w+)/(?P<category>\w+)/$", "analysis.views.filereport"),
    url(r"^full_memory/(?P<analysis_number>\w+)/$", "analysis.views.full_memory_dump_file"),
    url(r"^dashboard/", include("dashboard.urls")),
    url(r"^api/", include("api.urls")),
)
