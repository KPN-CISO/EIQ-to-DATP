#!/usr/bin/env python3

# (c) 2018 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>
# and Sebastiaan Groot <sebastiaang _monkeytail_ kpn-cert.nl> (for his
# EIQ lib)

# This software is GPLv3 licensed, except where otherwise indicated

import argparse
import datetime
import json
import pprint
import ssl
import time
import urllib

from eiqlib import eiqjson
from eiqlib import eiqcalls
from graphlib import graph
from config import settings


def transform(feedJSON, feedID, options):
    '''
    Take the EIQ JSON objects, extract all observables into lists,
    and transform those into the selected ruletypes.
    '''
    if options.verbose:
        print("U) Converting EIQ JSON objects into a group of entities ...")
    entities = []
    for entity in feedJSON:
        if 'extracts' in entity:
            if 'description' in entity['data']:
                description = entity['data']['description']
            if 'meta' in entity:
                meta = entity['meta']
                tlp = 'AMBER'
                if 'tlp_color' in meta:
                    tlp = meta['tlp_color']
                if 'title' in meta:
                    title = meta['title']
                    if description == '':
                        description = title
                if entity['extracts']:
                    entry = {title: {
                        'actor-id': [],
                        'description': [description],
                        'domain': [],
                        'email': [],
                        'email-subject': [],
                        'file': [],
                        'ipv4': [],
                        'ipv6': [],
                        'hash-md5': [],
                        'hash-sha1': [],
                        'hash-sha256': [],
                        'tlp': [tlp],
                        'uri': [],
                        'yara': []}}
                    for extract in entity['extracts']:
                        if 'kind' and 'value' in extract:
                            kind, value = extract['kind'], extract['value']
                            if kind == 'actor-id':
                                entry[title][kind].append(value)
                        if 'instance_meta' in extract:
                            instance_meta = extract['instance_meta']
                            if 'link_types' in instance_meta:
                                link_types = instance_meta['link_types']
                                if 'test-mechanism' in link_types:
                                    classification = ''
                                    if 'meta' in extract:
                                        meta = extract['meta']
                                        if 'classification' in meta:
                                            classification = meta['classification']
                                            if classification == 'bad':
                                                confidence = meta['confidence']
                                                entry[title]['confidence'] = confidence
                                                if kind in entry[title]:
                                                    entry[title][kind].append(value)
                    entities.append(entry)
    return(entities)


def createIndicators(entities, options):
    jsonIndicators = list()
    timeNow = int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())
    expirySeconds = timeNow + (settings.EXPIRY * 86400)
    expiryTime = str(datetime.datetime.utcfromtimestamp(expirySeconds).strftime("%Y-%m-%dT%H:%M:%SZ"))
    if options.verbose:
        print("U) Creating Indicators ...")
    if options.type == 'b':
        action = 'AlertAndBlock'
    elif options.type == 'a':
        action = 'Alert'
    elif options.type == 'p':
        action = 'Allowed'
    for entity in entities:
        for title in entity:
            observables = entity[title]
            description = title
            if observables['confidence']:
                confidence = observables['confidence']
                severity = confidence.capitalize()
            else:
                severity = 'Informational'
            application = settings.TAG
            if observables['domain']:
                for domain in observables['domain']:
                    jsonIndicator = dict()
                    jsonIndicator['indicatorValue'] = domain
                    jsonIndicator['indicatorType'] = 'DomainName'
                    jsonIndicator['title'] = title
                    jsonIndicator['description'] = description
                    jsonIndicator['application'] = application
                    jsonIndicator['expirationTime'] = expiryTime
                    jsonIndicator['action'] = action
                    jsonIndicator['severity'] = severity
                    jsonIndicator['recommendedActions'] = 'Report to ' + settings.ORG
                    jsonIndicators.append(jsonIndicator)
            if observables['hash-sha1']:
                for sha1 in observables['hash-sha1']:
                    jsonIndicator = dict()
                    jsonIndicator['indicatorValue'] = sha1
                    jsonIndicator['indicatorType'] = 'FileSha1'
                    jsonIndicator['title'] = title
                    jsonIndicator['description'] = description
                    jsonIndicator['application'] = application
                    jsonIndicator['expirationTime'] = expiryTime
                    jsonIndicator['action'] = action
                    jsonIndicator['severity'] = severity
                    jsonIndicator['recommendedActions'] = 'Report to ' + settings.ORG
                    jsonIndicators.append(jsonIndicator)
            if observables['hash-sha256']:
                for sha256 in observables['hash-sha256']:
                    jsonIndicator = dict()
                    jsonIndicator['indicatorValue'] = sha256
                    jsonIndicator['indicatorType'] = 'FileSha256'
                    jsonIndicator['title'] = title
                    jsonIndicator['description'] = description
                    jsonIndicator['application'] = application
                    jsonIndicator['expirationTime'] = expiryTime
                    jsonIndicator['action'] = action
                    jsonIndicator['severity'] = severity
                    jsonIndicator['recommendedActions'] = 'Report to ' + settings.ORG
                    jsonIndicators.append(jsonIndicator)
            if observables['ipv4']:
                for ipv4 in observables['ipv4']:
                    jsonIndicator = dict()
                    jsonIndicator['indicatorValue'] = ipv4
                    jsonIndicator['indicatorType'] = 'IpAddress'
                    jsonIndicator['title'] = title
                    jsonIndicator['description'] = description
                    jsonIndicator['application'] = application
                    jsonIndicator['expirationTime'] = expiryTime
                    jsonIndicator['action'] = action
                    jsonIndicator['severity'] = severity
                    jsonIndicator['recommendedActions'] = 'Report to ' + settings.ORG
                    jsonIndicators.append(jsonIndicator)
            if observables['ipv6']:
                for ipv6 in observables['ipv6']:
                    jsonIndicator = dict()
                    jsonIndicator['indicatorValue'] = ipv6
                    jsonIndicator['indicatorType'] = 'IpAddress'
                    jsonIndicator['title'] = title
                    jsonIndicator['description'] = description
                    jsonIndicator['application'] = application
                    jsonIndicator['expirationTime'] = expiryTime
                    jsonIndicator['action'] = action
                    jsonIndicator['severity'] = severity
                    jsonIndicator['recommendedActions'] = 'Report to ' + settings.ORG
                    jsonIndicators.append(jsonIndicator)
            if observables['uri']:
                for uri in observables['uri']:
                    jsonIndicator = dict()
                    jsonIndicator['indicatorValue'] = uri
                    jsonIndicator['indicatorType'] = 'Url'
                    jsonIndicator['title'] = title
                    jsonIndicator['description'] = description
                    jsonIndicator['application'] = application
                    jsonIndicator['expirationTime'] = expiryTime
                    jsonIndicator['action'] = action
                    jsonIndicator['severity'] = severity
                    jsonIndicator['recommendedActions'] = 'Report to ' + settings.ORG
                    #jsonIndicators.append(jsonIndicator)
    return(jsonIndicators)


def ingest(indicators, MSSCTOKEN, options):
    if options.verbose:
        print("U) Ingesting Indicators into Microsoft Security Center ...")
    sslcontext = ssl.create_default_context()
    if not settings.MSSCSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for MSSC, " +
                  "this is not recommended!")
        sslcontext.check_hostname = False
        sslcontext.verify_mode = ssl.CERT_NONE
    for indicator in indicators:
        uri = settings.MSSCAPIURL
        headers = {
            'Authorization': 'Bearer %s' % MSSCTOKEN,
            'Content-Type': 'application/json',
        }
        request = urllib.request.Request(uri, headers=headers)
        jsondata = json.dumps(indicator)
        jsondataasbytes = jsondata.encode('utf-8')
        request.add_header('Content-Length', len(jsondataasbytes))
        if options.verbose:
            print("Added Indicator:", jsondataasbytes)
        if options.simulate:
            print("U) Not ingesting anything into MSSC because simulate mode set!")
        else:
            response = urllib.request.urlopen(request, data=jsondataasbytes, context=sslcontext)
            time.sleep(0.6)
        if options.verbose:
            print("Slept a bit to not overload the API ...")


def download(feedID, options):
    '''
    Download the given feed number from the EclecticIQ JSON instance
    '''
    if not settings.EIQSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for EIQ, " +
                  "this is not recommended.")
    eiqAPI = eiqcalls.EIQApi(insecure=not(settings.EIQSSLVERIFY))
    eiqHost = settings.EIQHOST + settings.EIQVERSION
    eiqFeed = settings.EIQFEEDS + '/' + str(feedID) + '/runs/latest'
    eiqAPI.set_host(eiqHost)
    eiqAPI.set_credentials(settings.EIQUSER, settings.EIQPASS)
    eiqToken = eiqAPI.do_auth()
    eiqHeaders = {}
    eiqHeaders['Authorization'] = 'Bearer %s' % (eiqToken['token'],)
    try:
        if options.verbose:
            print("U) Contacting " + eiqHost + eiqFeed + ' ...')
        response = eiqAPI.do_call(endpt=eiqFeed,
                                  headers=eiqHeaders,
                                  method='GET')
    except IOError:
        print("E) An error occurred contacting the EIQ URL at " +
              eiqHost + eiqFeed)
        raise
    if not response or ('errors' in response):
        if response:
            for err in response['errors']:
                print('[error %d] %s' % (err['status'], err['title']))
                print('\t%s' % (err['detail'], ))
        else:
            print('unable to get a response from host')
            sys.exit(1)
    if 'content_blocks' not in response['data']:
        if options.verbose:
            print("E) No content blocks in feed ID!")
    else:
        if options.verbose:
            print("U) Attempting to download latest feed content ...")
        try:
            content_block = response['data']['content_blocks'][0]
            content_block = content_block.replace(settings.EIQVERSION, "")
            response = eiqAPI.do_call(endpt=content_block,
                                      headers=eiqHeaders,
                                      method='GET')
            if options.verbose:
                pprint.pprint(response)
            return response['entities']
        except IndexError:
            if 'entities' not in response:
                if options.verbose:
                    print("E) No entities in response!")
                    pprint.pprint(response)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='EIQ to DATP converter')
    parser.add_argument('-v', '--verbose',
                   dest='verbose',
                   action='store_true',
                   default=False,
                   help='[optional] Enable progress/error info (default: ' +
                        'disabled)')
    parser.add_argument('-t', '--type',
                   dest='type',
                   default='b',
                   help='[optional] Set the type of action rule you ' +
                        'wish to create: [a]lert, [b]lock or [p]ermit ('+
                        'default: block, which will also alert)')
    parser.add_argument('-s', '--simulate',
                   dest='simulate',
                   action='store_true',
                   default=False,
                   help='[optional] Do not actually generate anything, ' +
                        'just simulate everything. Mostly useful with ' +
                        'the -v/--verbose flag for debugging purposes.')
    parser.add_argument('-m', '--maliciousness',
                   dest='maliciousness',
                   default=None,
                   help='[optional] Override the default severity from the ' +
                        'EIQ indicators: [i]nfo, [l]ow, [m]edium or [h]igh')
    parser.add_argument('-f', '--feedID',
                   dest='feedID',
                   required=True,
                   default=None,
                   help='[required] The ID of the EclecticIQ feed to ingest')
    options = parser.parse_args()
    try:
        feedID = int(options.feedID)
    except ValueError:
        print("E) Please specify a numeric feedID!")
        raise
    if feedID:
        feedDict = download(feedID, options)
        if feedDict:
            entities = transform(feedDict, feedID, options)
            if entities:
                jsonIndicators = createIndicators(entities, options)
                if jsonIndicators:
                    MSSCTOKEN = graph.generateMSSCToken(options, settings)
                    ingest(jsonIndicators, MSSCTOKEN, options)
