#!/usr/bin/env python3

import json
import pprint
import ssl
import urllib


def generateMSSCToken(options, settings):
    if not options or not settings:
        print("U) Token library cannot be called without options or a settings file!")
        return None
    if options.verbose:
        print("U) Generating MSSC API token via " + settings.MSSCTOKENURI)
    try:
        MSSCTOKEN = None
        body = {
            'resource': settings.MSSCRESOURCEAPPIDURI,
            'client_id': settings.MSSCCLIENTID,
            'client_secret': settings.MSSCCLIENTSECRET,
            'grant_type': 'client_credentials'
        }
        sslcontext = ssl.create_default_context()
        if not settings.MSSCSSLVERIFY:
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
        uri = settings.MSSCTOKENURI
        data = urllib.parse.urlencode(body).encode('utf-8')
        request = urllib.request.Request(uri, data)
        response = urllib.request.urlopen(request, context=sslcontext)
        jsonResponse = json.loads(response.read().decode('utf-8'))
        if 'access_token' in jsonResponse:
            MSSCTOKEN = jsonResponse['access_token']
            if options.verbose:
                print("U) Got a MSSC API token:")
                pprint.pprint(MSSCTOKEN)
        else:
            print("U) No MSSC API token received!")
            raise
    except:
        print("U) Error contacting MSSC API endpoint!")
        raise
    return MSSCTOKEN


def generateGraphToken(options, settings):
    if not options or not settings:
        print("U) Token library cannot be called without options or a settings file!")
        return None
    if options.verbose:
        print("U) Generating Graph API token via " + settings.GRAPHTOKENURI)
    try:
        GRAPHTOKEN = None
        body = {
            'resource': settings.GRAPHRESOURCEAPPIDURI,
            'client_id': settings.GRAPHCLIENTID,
            'client_secret': settings.GRAPHCLIENTSECRET,
            'grant_type': 'client_credentials'
        }
        sslcontext = ssl.create_default_context()
        if not settings.GRAPHSSLVERIFY:
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
        uri = settings.GRAPHTOKENURI
        data = urllib.parse.urlencode(body).encode('utf-8')
        request = urllib.request.Request(uri, data)
        response = urllib.request.urlopen(request, context=sslcontext)
        jsonResponse = json.loads(response.read().decode('utf-8'))
        if 'access_token' in jsonResponse:
            GRAPHTOKEN = jsonResponse['access_token']
            if options.verbose:
                print("U) Got a Graph API token:")
                pprint.pprint(GRAPHTOKEN)
        else:
            print("U) No Graph API token received!")
            raise
    except:
        print("U) Error contacting Graph API endpoint!")
        raise
    return GRAPHTOKEN
