# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url
from analysis import views

urlpatterns = [
    url(r"^$", views.index),
    url(r"^page/(?P<page>\d+)/$", views.index),
    url(r"^(?P<task_id>\d+)/$", views.report),
    url(r"^surialert/(?P<task_id>\d+)/$", views.surialert),
    url(r"^surihttp/(?P<task_id>\d+)/$", views.surihttp),
    url(r"^suritls/(?P<task_id>\d+)/$", views.suritls),
    url(r"^surifiles/(?P<task_id>\d+)/$",views.surifiles),
    url(r"^antivirus/(?P<task_id>\d+)/$",views.antivirus),
    url(r"^shrike/(?P<task_id>\d+)/$", views.shrike),
    url(r"^remove/(?P<task_id>\d+)/$", views.remove),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", views.chunk),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/(?P<apilist>[!]?[A-Za-z_0-9,%]*)/$",
    views.filtered_chunk),
    url(r"^search/(?P<task_id>\d+)/$", views.search_behavior),
    url(r"^search/$", views.search),
    url(r"^pending/$", views.pending),
    url(r"^procdump/(?P<task_id>\d+)/(?P<process_id>\d+)/(?P<start>\w+)/(?P<end>\w+)/$",
    views.procdump),
    url(r"^(?P<task_id>\d+)/pcapstream/(?P<conntuple>[.,\w]+)/$", views.pcapstream),
    url(r"^(?P<task_id>\d+)/comments/$", views.comments),
]
