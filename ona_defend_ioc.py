#!/usr/bin/env python3
# Copyright 2020 Onapsis, Inc.
#
# Author: Onapsis Inc.
#

from argparse import ArgumentParser
from logging import basicConfig, DEBUG, INFO
import logging
import re
import os
import csv
import json
from collections import deque

APPLICATIONS_LOG_NAME = 'applications'
RESPONSES_LOG_NAME = 'responses'
JSON = 'json'
CSV = 'csv'
OUTPUT_FILENAME = 'output'
FILENAME_ANALYZED = 'File analyzed'
PERIOD_ANALYZED = 'Period analyzed'
TOTAL_EVENTS_ANALYZED = 'Total Events analyzed'
NUMBER_OF_IOCS_ANALYZED = 'Number of IoC\'s identified'
IOCS = 'IoCs'

class LogAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = filepath.split(os.sep)[-1]
        self.header = []
        self.events = []
        self.incidents = []

    def _get_version_from_header_line(self, line):
        return line.split('[')[1].split(']')[0][:3]

    def _parse_header(self):
        if self.header:
            return self.header
        else:
            with open(self.filepath, 'r') as file:
                line_counter = 0
                for line in file:
                    if line.startswith('<!--'):
                        self.header.append(line)
                    line_counter += 1

    def _get_log_name_from_header(self):
        '''
            <!--NAME[./log/system/httpaccess/responses_00.trc]/-->
            <!--NAME[./log/applications_00.log]/-->
        '''
        self._parse_header()
        for line in self.header:
            if 'NAME[' in line:
                return line.split('[')[1].split(']')[0]
    
    def _validate_log_header_version(self):
        '''
            <!--LOGGINGVERSION[2.0.7.1006]/-->
        '''
        for line in self.header:
            if 'LOGGINGVERSION' in line:
                log_version = self._get_version_from_header_line(line)
                if log_version == '2.0':
                    return
                else:
                    raise InvalidLogVersionException

        raise InvalidLogFormatException

    def _validate_nw_version(self):
        '''
            If NW version is present, check if it's >= 7.30
        '''
        self._parse_header()
        for line in self.header:
            if 'ENGINEVERSION' in line:
                nw_version = float(self._get_version_from_header_line(line))
                if nw_version >= 7.30:
                    return
                else:
                    raise NWNotVulnerableException

    def is_valid_log(self):
        log_name_path = self._get_log_name_from_header()
        return self.log_name in log_name_path.lower()

    def analyze_log(self):
        self._parse_header()
        self._validate_nw_version()
        self._validate_log_header_version()
        self._parse_events()
        self._events_sanitization()
        self._detect_incidents()


    def write_output_to_json(self, output_file):
        fd = open(output_file, 'w')
        output = {FILENAME_ANALYZED:self.filename,
                  PERIOD_ANALYZED: '[{}] --> [{}]'.format(self.events[0]['Date'], self.events[-1]['Date']),
                  TOTAL_EVENTS_ANALYZED: len(self.events),
                  NUMBER_OF_IOCS_ANALYZED: len(self.incidents),
                  IOCS: self.incidents
                 }
        json.dump(output, fd)


    def write_output_to_csv(self, output_file):
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([FILENAME_ANALYZED,self.filename])
            writer.writerow([PERIOD_ANALYZED, '[{}] --> [{}]'.format(self.events[0]['Date'], self.events[-1]['Date'])]),
            writer.writerow([TOTAL_EVENTS_ANALYZED,len(self.events)])
            writer.writerow([NUMBER_OF_IOCS_ANALYZED,len(self.incidents)])
            writer.writerow([IOCS])
            if self.incidents:
                csv_header = self.incidents[0].keys()
                writer.writerow(csv_header)
                for incident in self.incidents:
                    writer.writerow(incident.values()) 


    def print_quick_report(self, output_file):
        logging.info('{}: {}'.format(FILENAME_ANALYZED, self.filename))
        logging.info('=' * 30)
        logging.info('\t.) {}: [{}] --> [{}]'.format(PERIOD_ANALYZED, self.events[0]['Date'], self.events[-1]['Date']))
        logging.info('\t.) {}: {}'.format(TOTAL_EVENTS_ANALYZED, len(self.events)))
        logging.info('\t.) {}: {}'.format(NUMBER_OF_IOCS_ANALYZED, len(self.incidents)))
        logging.info('\t.) All detailed data was written to: {} '.format(output_file))
        logging.info('\n')

class APPSLogAnalyzer(LogAnalyzer):
    REGEX = r'''
            \#([^#]*)
            \#(?P<Date>[^#]*)
            \#(?P<Timezone>[^#]*)
            \#([^#]*)
            \#(?P<Category>[^#]*)
            \#(\n{0,1})
            \#([^#]*)
            \#(?P<RuntimeComponent>[^#]*)
            \#([^#]*)
            \#([^#]*)
            \#(?P<Application>[^#]*)
            \#(?P<Location>[^#]*)
            \#(?P<User>[^#]*)
            \#([^#]*)
            \#([^#]*)
            \#([^#]*)
            \#([^#]*)
            \#([^#]*)
            \#([^#]*)
            \#([^#]*)
            \#([^#]*)
            \#([^#]*)
            \#((?P<Message>[^#]*)(\#){1,2}[\r\n]*)
        '''
    COMPILED_REGEX = re.compile(REGEX, flags=re.VERBOSE | re.IGNORECASE)
    _incidents = [
        {'category': '/Applications/CTC/LIB'},
    ]

    def __init__(self, filepath):
        super().__init__(filepath)
        self.log_name = APPLICATIONS_LOG_NAME

    def _parse_events(self):
        self.events = []
        log_lines = deque(maxlen=3)
        with open(self.filepath, 'r') as file:
            for line in file:
                log_lines.append(line)
                match = re.match(self.COMPILED_REGEX, ''.join(log_lines))
                if match:
                    match_info = match.groupdict()
                    self.events.append(match_info)

    def _detect_incidents(self):
        for event in self.events:
            for incident in self._incidents:
                if event['Category'] == incident['category']:
                    self.incidents.append(event)

    def _events_sanitization(self):
        for i in range(len(self.events)):
            self.events[i]['Message'] = self.events[i]['Message'].strip()



class HTTPAccessLogAnalyzer(LogAnalyzer):
    REGEX = r'''
        \[(?P<Date>[0-9A-Za-z:,\s]+)\s*\]
        (.*\s|^)  # anything and a space after or the beginning
        (?P<client_ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})  # IP of the source
        \s*
        (.*\s(?P<username>\w+)\s)?  # username if present (optional)
        .*
        (\'|\s)
        (?P<http_method>\w+)  # HTTP verb
        \s  # space separator
        (?P<uri>.*) # URI that was accessed
        \s
        (HTTP\/1\.1)  # HTTP version
        .*
        \s  # space separator
        (?P<http_response_code>(\d){3})   # HTTP status code of the response
        \s  # space separator
        \d+
        .*
    '''
    COMPILED_REGEX = re.compile(REGEX, flags=re.VERBOSE | re.IGNORECASE)
    _incidents = [
        {'method': 'POST', 'uri': '/CTCWebService/CTCWebServiceBean'},
        {'method': 'POST', 'uri': '/EemAdminService/EemAdmin'},
    ]

    def __init__(self, filepath):
        super().__init__(filepath)
        self.log_name = RESPONSES_LOG_NAME

    def _parse_events(self):
        self.events = []
        with open(self.filepath, 'r') as file:
            for line in file:
                match = re.match(self.COMPILED_REGEX, line)
                if match:
                    match_info = match.groupdict()
                    self.events.append(match_info)

    def _detect_incidents(self):
        for event in self.events:
            for incident in self._incidents:
                if event['http_method'] == incident['method'] and\
                        incident['uri'] in event['uri'] and\
                        event['http_response_code'] == '200':
                    self.incidents.append(event)

    def _events_sanitization(self):
         for i in range(len(self.events)):
            self.events[i]['Date'] = self.events[i]['Date'].strip()

class InvalidLogFormatException(Exception):
    pass
class InvalidLogVersionException(Exception):
    pass

class NWNotVulnerableException(Exception):
    pass


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-f', dest='filepath', required=True,\
                        help='SAP JAVA logfile to look for IoCs')
    parser.add_argument('-o', dest='output_type', required=True,\
                        choices=[CSV,JSON], help='Output type')
    parser.add_argument('--debug', dest='debug', action='store_true', \
                        help='Set this flag if for debug messages')
    args = parser.parse_args()
    basicConfig(format='%(levelname)s:%(message)s', level=DEBUG if args.debug else INFO)

    found_valid = False
    try:
        for cl in [APPSLogAnalyzer, HTTPAccessLogAnalyzer]:
            analyzer = cl(args.filepath)
            if analyzer.is_valid_log():
                found_valid = True
                analyzer.analyze_log()
                break
        if not found_valid:
            logging.error('[-] Invalid File format detected. Valid name not found in log\'s header')
            exit(1)
    
    except InvalidLogVersionException as e:
        logging.error('[-] The submitted log\'s version is unsupported')
        logging.exception(e)
    
    except NWNotVulnerableException as e:
        logging.error('[-] The submitted log\'s seems to be from a NetWeaver JAVA older than 7.30. Therefore is not vulnerable. No analysis will be performed')
        logging.exception(e)

    except InvalidLogFormatException as e:
        logging.error('[-] The submitted log has not a valid format')
        logging.exception(e)

    except Exception as e:
        logging.exception(e)
    else:
        output_file = '{}_onadefend_iocs_output.{}'.format(analyzer.filename, args.output_type)
        if args.output_type == JSON:
            analyzer.write_output_to_json(output_file)
        elif args.output_type == CSV:
            analyzer.write_output_to_csv(output_file)
        
        analyzer.print_quick_report(output_file)
