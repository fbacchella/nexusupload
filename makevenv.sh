#!/usr/bin/bash
MINOR=${MINOR:-7}
VENV=$PWD/venv3${MINOR}.${HWNAME}
PYTHONCMD=$(command -v python3.$MINOR)

virtualenv-3 -p $PYTHONCMD $VENV
PYCURL_CURL_CONFIG=$(type -p curl-config) PYCURL_SSL_LIBRARY=${PYCURL_SSL_LIBRARY:-openssl} $VENV/bin/python setup.py install
