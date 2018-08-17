#!/usr/bin/bash

VENV=$PWD/venv34
virtualenv-3.4 $VENV
PATH=/opt/local/bin:$PATH PYCURL_SSL_LIBRARY=openssl $VENV/bin/python setup.py install
