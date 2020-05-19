#!/usr/bin/env python3

# (c) 2020 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>

# This software is GPLv3 licensed, except where otherwise indicated

import argparse
import json
import pprint
import requests
import ssl
import urllib

from graphlib import graph
from config import settings


def deleteIndicator(options, id, MSSCTOKEN):
    '''
    Download Custom Indicators
    '''
    if options.verbose:
        print("U) Downloading Custom Indicators ...")

    url = settings.MSSCURL + '/indicators/' + id
    apiheaders = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + MSSCTOKEN
    }
    if not settings.MSSCSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for MSSC, " +
                  "this is not recommended!")
        sslcontext = ssl.create_default_context()
        sslcontext.check_hostname = False
        sslcontext.verify_mode = ssl.CERT_NONE
    if options.verbose:
        print("U) Deleting " + url + " ...")
    if not options.simulate:
        try:
            r = requests.delete(url, headers=apiheaders)
            if options.verbose:
                print("U) Got a JSON response:")
                print(r)
        except IOError:
            if options.verbose:
                print("E) An error occured deleting the indicator!")
            raise
    else:
        print("U) Not deleting anything because simulate mode is set!")


def download(options, MSSCTOKEN):
    try:
        '''
        Download Custom Indicators
        '''
        if options.verbose:
            print("U) Downloading Custom Indicators ...")

        url = settings.MSSCURL + '/indicators/'
        apiheaders = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + MSSCTOKEN
        }
        if options.verbose:
            print("U) Contacting " + url + " ...")
        if not settings.MSSCSSLVERIFY:
            if options.verbose:
                print("W) You have disabled SSL verification for MSSC, " +
                      "this is not recommended!")
            sslcontext = ssl.create_default_context()
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers=apiheaders)
            response = urllib.request.urlopen(req, context=sslcontext)
        else:
            req = urllib.request.Request(url, headers=apiheaders)
            response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read().decode('utf-8'))
        if options.verbose:
            print("U) Got a JSON response package:")
            pprint.pprint(jsonResponse)
        return (jsonResponse['value'])
    except IOError:
        if options.verbose:
            print("E) An error occured downloading indicators!")
        raise


def main():
    parser = argparse.ArgumentParser(description='Delete Indicator from MSSC')
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true',
                        default=False,
                        help='[optional] Enable verbosity (default: disabled)')
    parser.add_argument('-s', '--simulate',
                        dest='simulate',
                        action='store_true',
                        default=False,
                        help='[optional] Do not actually ingest anything into '
                             'EIQ, just simulate everything. Mostly useful '
                             'with the -v/--verbose flag.')
    parser.add_argument('-i', '--indicator(s)',
                        dest='indicators',
                        default=None,
                        required=False,
                        nargs='*',
                        help='[required] List of indicators to delete, e.g. a '
                             'SHA1 hash: 3395856ce81f2b7382dee72602f798b642f1'
                             '4140. If you do not specify an indicator, this '
                             'script will print an overview of all current '
                             'Custom Indicators if verbose mode is enabled.')
    args = parser.parse_args()
    MSSCTOKEN = graph.generateMSSCToken(args, settings)
    customIndicators = download(args, MSSCTOKEN)
    if customIndicators:
        if not args.indicators:
            for customIndicator in customIndicators:
                customIndicatorType = str(customIndicator['indicatorType'])
                customIndicatorValue = str(customIndicator['indicatorValue'])
                if args.verbose:
                    print('Type:', customIndicatorType, '- Value:',
                          customIndicatorValue)
        else:
            for customIndicator in customIndicators:
                customIndicatorValue = str(customIndicator['indicatorValue'])
                for indicator in args.indicators:
                    if customIndicator['indicatorValue'] == indicator:
                        indicatorId = customIndicator['id']
                        deleteIndicator(args, indicatorId, MSSCTOKEN)


if __name__ == "__main__":
    main()
