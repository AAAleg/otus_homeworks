#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import logging
import os
import re
import gzip
import argparse
import configparser
from datetime import datetime
from collections import defaultdict, namedtuple
from statistics import median
from string import Template

SECTION = 'CONFIG'

CONFIG = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "REPORT_TEMPLATE_DIR": "./report_template",
    "REPORT_TEMPLATE": "report.html",
    "REPORT_NAME_PATTERN": "report-{}.html",
    "REPORT_DATE_FORMAT": "%Y.%m.%d",
    "LOG_DATE_FORMAT": "%Y%m%d",
    "ERROR_PERCENT_RESTRICTION": 0.1,
    "SCRIPT_LOG_NAME": "log_analyzer",
    "SCRIPT_LOG_DIR": "./log",
}

LOG_FILE_PATTERN = re.compile(r'nginx-access-ui.log-(?P<date>\d{8})(\.gz)?$')

LOG_PATTERN = re.compile(
    r'(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s'
    r'(?P<remote_user>\S+)\s+'  
    r'(?P<http_x_real_ip>\S+)\s+'
    r'\[(?P<time_local>.+)\]\s+'
    r'"(?P<request_method>\S+)\s+'
    r'(?P<request_url>\S+)\s+'
    r'(?P<request_protocol>\S+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<body_bytes_sent>\d+)\s+'
    r'"(?P<http_referer>.+)"\s+'
    r'"(?P<http_user_agent>.+)"\s+'
    r'"(?P<http_x_forwarded_for>.+)"\s+'
    r'"(?P<http_X_REQUEST_ID>.+)"\s+'
    r'"(?P<http_X_RB_USER>.+)"\s+'
    r'(?P<request_time>.+)'
)

Log = namedtuple('Log', ['path', 'date'])


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', nargs='?', default='config.ini')
    return parser.parse_args()


def parse_config(path):
    config = {}
    if os.path.exists(path):
        configfile = configparser.ConfigParser(defaults=CONFIG)
        configfile.read(path)
        section = SECTION if configfile.has_section(SECTION) else 'DEFAULT'
        for option in CONFIG:
            config[option] = configfile.get(section, option, raw=True)
    return config


def logging_setting(config):
    default_dir = os.path.dirname(os.path.abspath(__file__))
    config_dir = config.get('SCRIPT_LOG_DIR', default_dir)
    if not os.path.exists(config_dir):
        config_dir = default_dir
    name = config.get('SCRIPT_LOG_NAME', CONFIG['SCRIPT_LOG_NAME'])
    logging.basicConfig(
        format='[%(asctime)s] %(levelname)s %(message)s',
        datefmt='%Y.%m.%d %H:%M:%S',
        level=logging.INFO,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("{0}/{1}.log".format(config_dir, name))
        ],
    )


def validate(conf):
    if not conf:
        logging.error('No config.ini file')
    elif not os.path.exists(conf['LOG_DIR']):
        logging.error('No log dir: {}'.format(conf['LOG_DIR']))
    elif not os.path.exists(os.path.join(conf['REPORT_TEMPLATE_DIR'], conf['REPORT_TEMPLATE'])):
        logging.error('No template file: {}'.format(conf['REPORT_TEMPLATE']))
    else:
        return True
    return False


def find_last_log(log_dir, format):
    log = None
    for path in os.listdir(log_dir):
        try:
            filedate = LOG_FILE_PATTERN.match(path).group('date')
            date = datetime.strptime(filedate, format).date()
        except (ValueError, AttributeError):
            continue
        if not log or log.date < date:
            log = Log(path=os.path.join(log_dir, path), date=date)
    return log


def read_logs(log_path):
    log_open = gzip.open if log_path.endswith(".gz") else open
    with log_open(log_path, 'rb') as log:
        for line in log:
            yield line.decode('utf-8')


def parse_log(log, error_percent):
    requests = defaultdict(lambda: {'count': 0, 'request_time': []})
    good_log = 0
    bad_log = 0
    for row in read_logs(log.path):
        try:
            entry = LOG_PATTERN.match(row).groupdict()
            requests[entry['request_url']]['count'] += 1
            requests[entry['request_url']]['request_time'].append(float(entry['request_time']))
            good_log += 1
        except AttributeError:
            bad_log += 1

        if bad_log / good_log > error_percent:
            raise ValueError

    return requests, error_percent


def get_request_statistics(requests):
    statistics = []
    for url in requests:
        requests[url]['time_sum'] = sum(requests[url]['request_time'])
    total_count = sum((requests[url]['count'] for url in requests))
    total_time = sum((requests[url]['time_sum'] for url in requests))
    for url in requests:
        statistics.append({
            'url': url,
            'count': requests[url]['count'],
            'time_sum':  requests[url]['time_sum'],
            'count_perc': 100 * requests[url]['count'] / total_count,
            'time_perc': 100 * requests[url]['time_sum'] / total_time,
            'time_avg': requests[url]['time_sum'] / requests[url]['count'],
            'time_max': max(requests[url]['request_time']),
            'time_med': median(requests[url]['request_time']),
        })
    return statistics


def get_table_json(statistics, size):
    limited_list_requests = sorted(
        statistics,
        key=lambda request: request['count'],
        reverse=True
    )[:size]
    row = str(
        '{{"url":"{url}", '
        '"count_perc":"{count_perc:.2f}", '
        '"time_perc":"{time_perc:.2f}", '
        '"time_avg":"{time_avg:.2f}", '
        '"count":"{count}", '
        '"time_med":"{time_med:.2f}", '
        '"time_max":"{time_max:.2f}", '
        '"time_sum":"{time_sum:.2f}"}}'
    )
    table_json = '[{}]'.format(', '.join(
        row.format(**request) for request in limited_list_requests
    ))
    return table_json


def create_report(statistics, report_path, template_path, size):
    table_json = get_table_json(statistics, size)
    with open(template_path, 'r') as template, open(report_path, 'w') as report:
        report.write(Template(template.read()).safe_substitute({'table_json': table_json}))


def report(config):
    # Firstly, we are looking for the most recent file of logs
    last_log = find_last_log(config['LOG_DIR'], config['LOG_DATE_FORMAT'])
    if not last_log:
        logging.info('No find log in dir {}'.format(config['LOG_DIR']))
        return
    else:
        logging.info('Find log {}'.format(last_log.path))

    # Secondly, to check whether there is already a prepared report file

    if not os.path.exists(config['REPORT_DIR']):
        os.mkdir(config['REPORT_DIR'])

    log_date = last_log.date.strftime(config['REPORT_DATE_FORMAT'])
    report_path = os.path.join(config['REPORT_DIR'], config['REPORT_NAME_PATTERN'].format(log_date))

    if os.path.exists(report_path):
        logging.info('For today the report is already prepared')
        return

    # Third, parse a logfile

    try:
        requests, error_rate = parse_log(last_log, config['ERROR_PERCENT_RESTRICTION'])
    except ValueError:
        logging.error("Error rate {} isn't acceptable {}".format(error_rate, config['ERROR_PERCENT_RESTRICTION']))
        return

    # In the end, we count the statistics and create a report
    template_path = os.path.join(
        config['REPORT_TEMPLATE_DIR'], config['REPORT_TEMPLATE'])
    statistics = get_request_statistics(requests)
    create_report(
        statistics=statistics,
        report_path=report_path,
        template_path=template_path,
        size=int(config['REPORT_SIZE'])
    )
    logging.info('File {} create'.format(report_path))


def main():
    args = parse_args()
    config = parse_config(path=args.config)
    logging_setting(config)
    if validate(config):
        report(config)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception(e)
