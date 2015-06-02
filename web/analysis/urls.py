# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "analysis.views.index"),
    url(r"^page/(?P<page>\d+)/$", "analysis.views.index"),
    url(r"^(?P<task_id>\d+)/$", "analysis.views.report"),
    url(r"^remove/(?P<task_id>\d+)/$", "analysis.views.remove"),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", "analysis.views.chunk"),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/(?P<apilist>[!]?[A-Za-z_0-9,%]*)/$", "analysis.views.filtered_chunk"),
    url(r"^search/(?P<task_id>\d+)/$", "analysis.views.search_behavior"),
    url(r"^search/$", "analysis.views.search"),
    url(r"^pending/$", "analysis.views.pending"),
    url(r"^procdump/(?P<object_id>\w+)/(?P<task_id>\d+)/(?P<process_id>\d+)/(?P<start>\w+)/(?P<end>\w+)/$", "analysis.views.procdump"),
    url(r"^(?P<task_id>\d+)/pcapstream/(?P<conntuple>[.,\w]+)/$", "analysis.views.pcapstream"),
    url(r"^(?P<task_id>\d+)/comments/$", "analysis.views.comments"),
)
