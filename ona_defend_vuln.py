#!/usr/bin/env python3
# Copyright 2020 Onapsis, Inc.
#
# Author: Onapsis Inc.
#

import requests
import json
from urllib.parse import urlparse
from argparse import ArgumentParser
from logging import basicConfig, DEBUG, INFO
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CVE_tester():
    def __init__(self, url, debug=False):
        o = urlparse(url)
        self.url = o.scheme + '://' + o.netloc
        self.debug = debug

    def run_vulnerability_test(self):
        try:
            r = requests.get(self.url, allow_redirects=False, verify=False)
        except Exception as e:
            logging.error("Error connecting to {} - ({})".format(self.url, str(e)))
            return -1
        status_code = self._get_app_status_code()
        if status_code == 200:
            logging.info("{} Vulnerability was detected in application URL {}" \
                         .format(self._cve_id, self.url))
            return {"CVE": self._cve_id,
                    "CVSS": self._cvss,
                    "Vunerable URL": self.url,
                    "Vulnerability description": "{} Vulnerability was detected".format(self._cve_id)}
        else:
            asset_version = self._get_server_version(r)
            if asset_version >= self._nw_version or asset_version == 0:
                # If version was not identified or version matches potentially vulnerable
                logging.info("{} vulnerability was not detected in application URL {} (code {})"\
                             .format(self._cve_id, self.url, status_code))
            else:
                logging.info("Based on the server version ({}), application URL {} should not be vulnerable to {}".format( asset_version, self.url, self._cve_id))
        
    def _get_app_status_code(self):
        request_body = self._request_body
        app_url = self.url + self._app_name
        headers = {'content-type': 'text/xml'}
        response = requests.post(app_url, headers=headers, allow_redirects=False, verify=False, data=request_body)
        logging.debug("App response code: {}".format(response.status_code))
        return response.status_code

    def _get_server_version(self, http_response):
        server = ""
        version = "0"
        try:
            if 'server' in http_response.headers:
                server = http_response.headers['server']
            else:
                return 0
            version = int(server[-4:].replace(".", "").replace(" ", ""))
            logging.debug("pVersion identified {}".format(version))
        except Exception:
            logging.debug("Unexpected server header: {}".format(server))
        return version


class CVE_2020_6287_tester(CVE_tester):
    _request_body = """
        <x:Envelope
            xmlns:x="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:urn="urn:CTCWebServiceSi">
            <x:Header/>
            <x:Body>
                <urn:initializeConnection>
                    <urn:conndata></urn:conndata>
                </urn:initializeConnection>
            </x:Body>
        </x:Envelope>
        """
    _cve_id = "CVE-2020-6287"
    _app_name = "/CTCWebService/CTCWebServiceBean"
    _cvss = 10
    _nw_version = 730


class CVE_2020_6207_tester(CVE_tester):
    _request_body = """
        <x:Envelope
            xmlns:x="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:adm="http://sap.com/smd/eem/admin/">
            <x:Header/>
            <x:Body>
                <adm:getAllAgentInfo></adm:getAllAgentInfo>
            </x:Body>
        </x:Envelope>
        """
    _app_name = "/EemAdminService/EemAdmin"
    _cve_id = "CVE-2020-6207"
    _cvss = 10
    _nw_version = 740


if __name__ == "__main__":
    parser = ArgumentParser(description="Author: Onapsis Inc. ")
    parser.add_argument("-u", dest="url", help="SAP JAVA URL to test")
    parser.add_argument("-f", dest="filename", help="Filename with SAP JAVA URLs (one per line)")
    parser.add_argument("--debug", dest="debug", action="store_true", \
                        help="Set this flag if for debug messages")
    args = parser.parse_args()
    if not args.url and not args.filename:
        parser.error("Missing arguments. Either filename or url should be provided.")
    
    basicConfig(format='%(levelname)s:%(message)s', level=DEBUG if args.debug else INFO)
    cve_list = [
        CVE_2020_6287_tester,
        CVE_2020_6207_tester
        ]
    if args.url:
        for v in cve_list:
            assess = v(args.url)
            res = assess.run_vulnerability_test()
            if res and res != -1:
                print([res])

    elif args.filename:
        with open(args.filename,'r') as f:
            urls = f.readlines()
        all_vulnerable_data = []
        for url in urls:
            for v in cve_list:
                assess = v(url.strip())
                vuln_data = assess.run_vulnerability_test()
                if vuln_data and vuln_data != -1:
                    all_vulnerable_data.append(vuln_data)
        print(json.dumps(all_vulnerable_data))