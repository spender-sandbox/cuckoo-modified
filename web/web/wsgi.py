# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
WSGI config for web project.

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

Usually you will have the standard Django WSGI application here, but it also
might make sense to replace the whole Django WSGI application with a custom one
that later delegates to the Django one. For example, you could introduce WSGI
middleware here, or combine a Django application with an application of another
framework.

"""
import os

"""

:: Correctly setting up WSGI w/ Apache2, using only HTTPS. Start here.

You can use the following command to generate SSL certs for an HTTPS setup.
# sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout \ 
    /etc/apache2/ssl/cert.key -out /etc/apache2/ssl/cert.crt

The following Apache2 vhost will work plug-and-play with the above command
// Begin Apache2 config for WSGI usage

<VirtualHost *:443>

        # Remember to change paths where necessary

        SSLEngine On
        SSLCertificateFile      /etc/apache2/ssl/cert.crt
        SSLCertificateKeyFile   /etc/apache2/ssl/cert.key

        WSGIDaemonProcess web processes=5 threads=20

        WSGIScriptAlias         /       /opt/cuckoo/cuckoo-modified/web/web/wsgi.py

        <Directory /opt/cuckoo/cuckoo-modified/web>
                Require         all     granted
                WSGIScriptReloading On
        </Directory>

        Alias /static /opt/cuckoo/cuckoo-modified/web/static

        ErrorLog        ${APACHE_LOG_DIR}/error.log
        LogLevel        error
        CustomLog       ${APACHE_LOG_DIR}/access.log    combined

</VirtualHost>

// End Apache2 config for WSGI usage

Uncomment and edit the following lines to match your install location
"""
#import sys
#sys.path.append('/path/to/cuckoo-modified')
#sys.path.append('/path/to/cuckoo-modified/web')
#os.chdir('/path/to/cuckoo-modified/web')

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")

# This application object is used by any WSGI server configured to use this
# file. This includes Django's development server, if the WSGI_APPLICATION
# setting points here.
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

# Apply WSGI middleware here.
# from helloworld.wsgi import HelloWorldApplication
# application = HelloWorldApplication(application)
