import re
import os
import calendar
from insightlog.settings import *
from insightlog.validators import *
from datetime import datetime
import argparse
import logging
logging.basicConfig(level=logging.INFO)
import json
import csv
import io


def get_service_settings(service_name):
    """
    Get default settings for the said service
    :param service_name: service name (example: nginx, apache2...)
    :return: service settings if found or None
    """
    if service_name in SERVICES_SWITCHER:
        return SERVICES_SWITCHER.get(service_name)
    else:
        raise Exception("Service \""+service_name+"\" doesn't exists!")


def get_date_filter(settings, minute=datetime.now().minute, hour=datetime.now().hour,
                    day=datetime.now().day, month=datetime.now().month,
                    year=datetime.now().year):
    """
    Get the date pattern that can be used to filter data from logs based on the params
    :raises Exception:
    :param settings: dict
    :param minute: int
    :param hour: int
    :param day: int
    :param month: int
    :param year: int
    :return: string
    """
    if not is_valid_year(year) or not is_valid_month(month) or not is_valid_day(day) \
            or not is_valid_hour(hour) or not is_valid_minute(minute):
        raise Exception("Date elements aren't valid")
    if minute != '*' and hour != '*':
        date_format = settings['dateminutes_format']
        date_filter = datetime(year, month, day, hour, minute).strftime(date_format)
    elif minute == '*' and hour != '*':
        date_format = settings['datehours_format']
        date_filter = datetime(year, month, day, hour).strftime(date_format)
    elif minute == '*' and hour == '*':
        date_format = settings['datedays_format']
        date_filter = datetime(year, month, day).strftime(date_format)
    else:
        raise Exception("Date elements aren't valid")
    return date_filter


def filter_data(log_filter, data=None, filepath=None, is_casesensitive=True, is_regex=False, is_reverse=False):
    """
    Filter received data/file content and return the results
    :except IOError:
    :except EnvironmentError:
    :raises Exception:
    :param log_filter: string
    :param data: string
    :param filepath: string
    :param is_casesensitive: boolean
    :param is_regex: boolean
    :param is_reverse: boolean to inverse selection
    :return: string
    """
    # BUG: This function returns None on error instead of raising -- Done(Akar)
    # BUG: No encoding handling in file reading (may crash on non-UTF-8 files) -- Done(Akar)
    # TODO: Log errors/warnings instead of print -- Done(Akar)
    return_data = ""
    if filepath:
        try:
            with open(filepath, 'r', encoding='utf-8') as file_object:
                for line in file_object:
                    if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                        return_data += line
            return return_data
        except (IOError, EnvironmentError) as e:
            logging.error(f"Error reading file {filepath}: {e}")
            #print(e.strerror)
            # TODO: Log error instead of print
            # raise  # Should raise instead of just printing
            raise Exception("Error reading file: " + str(e))
    # If data is provided, filter it directly
    elif data:
        for line in data.splitlines():
            if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                return_data += line+"\n"
        return return_data
    else:
        # TODO: Better error message for missing data/filepath - Done(Akar)
        raise Exception("Valid Data or filepath must be provided for filtering.")


def check_match(line, filter_pattern, is_regex, is_casesensitive, is_reverse):
    """
    Check if line contains/matches filter pattern
    :param line: string
    :param filter_pattern: string
    :param is_regex: boolean
    :param is_casesensitive: boolean
    :param is_reverse: boolean
    :return: boolean
    """
    if is_regex:
        check_result = re.match(filter_pattern, line) if is_casesensitive \
            else re.match(filter_pattern, line, re.IGNORECASE)
    else:
        check_result = (filter_pattern in line) if is_casesensitive else (filter_pattern.lower() in line.lower())
    return check_result and not is_reverse


def get_web_requests(data, pattern, date_pattern=None, date_keys=None):
    """
    Analyze data (from the logs) and return list of web requests in unified format.
    :param data: string
    :param pattern: string
    :param date_pattern: regex|None
    :param date_keys: dict|None
    :return: list of dicts
    """
     # BUG: Output format inconsistent with get_auth_requests - Done
    # BUG: No handling/logging for malformed lines - Done
    if date_pattern and not date_keys:
        raise Exception("date_keys is not defined")
    requests_dict = re.findall(pattern, data, flags=re.IGNORECASE)
    requests = []
    for request_tuple in requests_dict:
        str_datetime = __get_iso_datetime(request_tuple[1], date_pattern, date_keys) if date_pattern else request_tuple[1]
        requests.append({
            'TYPE': 'web',
            'DATETIME': str_datetime,
            'IP': request_tuple[0],
            'METHOD': request_tuple[2],
            'ROUTE': request_tuple[3],
            'CODE': request_tuple[4],
            'REFERRER': request_tuple[5],
            'USERAGENT': request_tuple[6],
            'SERVICE': None,
            'INVALID_USER': None,
            'INVALID_PASS_USER': None,
            'IS_PREAUTH': None,
            'IS_CLOSED': None
        })
    return requests


def get_auth_requests(data, pattern, date_pattern=None, date_keys=None):
    """
    Analyze data (from the logs) and return list of auth requests in unified format.
    :param data: string
    :param pattern: string
    :param date_pattern: regex|None
    :param date_keys: dict|None
    :return: list of dicts
    """
    requests_dict = re.findall(pattern, data)
    requests = []
    for request_tuple in requests_dict:
        str_datetime = __get_iso_datetime(request_tuple[0], date_pattern, date_keys) if date_pattern else request_tuple[0]
        parsed = analyze_auth_request(request_tuple[2])
        parsed.update({  # type: ignore
            'TYPE': 'auth',
            'DATETIME': str_datetime,
            'SERVICE': request_tuple[1],
            'METHOD': None,
            'ROUTE': None,
            'CODE': None,
            'REFERRER': None,
            'USERAGENT': None
        })
        requests.append(parsed)
    return requests


def analyze_auth_request(request_info):
    """
    Analyze request info and returns main data (IP, invalid user, invalid password's user, is_preauth, is_closed)
    :param request_info: string
    :return: dict
    """
    # BUG: No handling/logging for malformed lines  - Done
    try:
        ipv4 = re.findall(IPv4_REGEX, request_info)
        invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
        invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)
        is_preauth = '[preauth]' in request_info.lower()
        is_closed = 'connection closed by ' in request_info.lower()

        return {
            'IP': ipv4[0] if ipv4 else None,
            'INVALID_USER': invalid_user[0] if invalid_user else None,
            'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
            'IS_PREAUTH': is_preauth,
            'IS_CLOSED': is_closed
        }

    except Exception as e:
        print(f"[!] Malformed auth log line: {request_info} — {e}")
        return {
            'IP': None,
            'INVALID_USER': None,
            'INVALID_PASS_USER': None,
            'IS_PREAUTH': None,
            'IS_CLOSED': None
        }
def __get_iso_datetime(str_date, pattern, keys):
    """
    Change raw datetime from logs to ISO 8601 format.
    :param str_date: string
    :param pattern: regex (date_pattern from settings)
    :param keys: dict (date_keys from settings)
    :return: string
    """
    months_dict = {v: k for k, v in enumerate(calendar.month_abbr)}
    a_date = re.findall(pattern, str_date)[0]
    d_datetime = datetime(int(a_date[keys['year']]) if 'year' in keys else __get_auth_year(),
                          months_dict[a_date[keys['month']]], int(a_date[keys['day']].strip()),
                          int(a_date[keys['hour']]), int(a_date[keys['minute']]), int(a_date[keys['second']]))
    return d_datetime.isoformat(' ')


def __get_auth_year():
    # TODO: Add support for analysis done in different terms
    """
    Return the year when the requests happened so there will be no bug if the analyze is done in the new year eve,
    the library was designed to be used for hourly analysis.
    :return: int
    """
    if datetime.now().month == 1 and datetime.now().day == 1 and datetime.now().hour == 0:
        return datetime.now().year - 1
    else:
        return datetime.now().year


class InsightLogAnalyzer:

    def __init__(self, service, data=None, filepath=None):
        """
        Constructor, define service (nginx, apache2...), set data or filepath if needed
        :param service: string: service name (nginx, apache2...)
        :param data: string: data to be filtered if not from a file
        :param filepath: string: file path from which the data will be loaded if data isn't defined
        and you are not using the default service logs filepath
        :return:
        """
        self.__filters = []
        self.__settings = get_service_settings(service)
        self.data = data
        if filepath:
            self.filepath = filepath
        else:
            self.filepath = self.__settings['dir_path']+self.__settings['accesslog_filename']

    def add_filter(self, filter_pattern, is_casesensitive=True, is_regex=False, is_reverse=False):
        """
        Add filter data the filters list
        :param filter_pattern: boolean
        :param is_casesensitive: boolean
        :param is_regex: boolean
        :param is_reverse: boolean
        :return:
        """
        self.__filters.append({
            'filter_pattern': filter_pattern,
            'is_casesensitive': is_casesensitive,
            'is_regex': is_regex,
            'is_reverse': is_reverse
        })

    def add_date_filter(self, minute=datetime.now().minute, hour=datetime.now().hour,
                        day=datetime.now().day, month=datetime.now().month, year=datetime.now().year):
        """
        Set datetime filter
        :param minute: int
        :param hour: int
        :param day: int
        :param month: int
        :param year: int
        """
        date_filter = get_date_filter(self.__settings, minute, hour, day, month, year)
        self.add_filter(date_filter)

    def get_all_filters(self):
        """
        return all defined filters
        :return: List
        """
        return self.__filters

    def get_filter(self, index):
        """
        Get a filter data by index
        :param index:
        :return: Dictionary
        """
        return self.__filters[index]

    def remove_filter(self, index):
        """
        Remove one filter from filters list using its index
        :param index: int
        :return:
        """
        try:
            del self.__filters[index]
        except IndexError:
            raise Exception(f"Filter index {index} is out of range.")
    

    def clear_all_filters(self):
        """
        Clear all filters
        :return:
        """
        self.__filters = []

    def check_all_matches(self, line, filter_patterns):
        """
        Check if line contains/matches all filter patterns
        :param line: String
        :param filter_patterns: List of dictionaries containing
        :return: boolean
        """
        if not filter_patterns:
            return True  # No filters means include all lines
        to_return = None
        for pattern_data in filter_patterns:
            tmp_result = check_match(line=line, **pattern_data)
            to_return = tmp_result if to_return is None else (tmp_result and to_return)
        return to_return

    def filter_all(self):
        """
        Apply all defined patterns and return filtered data
        :return: string
        """
        # BUG: Large files are read into memory at once (performance issue)
        # BUG: No warning or log for empty files - Done
        to_return = ""
        if self.data:
            for line in self.data.splitlines():
                if self.check_all_matches(line, self.__filters):
                    to_return += line+"\n"
        else:
             with open(self.filepath, 'r', encoding='utf-8') as file_object:
                    # lines = file_object.readlines()
                    # if not lines:
                    #     raise Exception("The file is empty.")
                    # for line in lines:
                    #     if self.check_all_matches(line, self.__filters):
                    #         to_return += line
                has_data = False
                for line in file_object:
                    has_data = True
                    if self.check_all_matches(line, self.__filters):
                        to_return += line
                if not has_data:
                    raise Exception("The file is empty.")
        return to_return

    def get_requests(self, format='list'):
         # TODO: Add support for CSV and JSON output
        """
        Analyze data (from the logs) and return list of requests formatted as the model (pattern) defined.
        :param format: string - 'list', 'json', or 'csv'
        :return: list, JSON string, or CSV string
        """
        data = self.filter_all()
        request_pattern = self.__settings['request_model']
        date_pattern = self.__settings['date_pattern']
        date_keys = self.__settings['date_keys']

        if self.__settings['type'] == 'web0':
            requests = get_web_requests(data, request_pattern, date_pattern, date_keys)
        elif self.__settings['type'] == 'auth':
            requests = get_auth_requests(data, request_pattern, date_pattern, date_keys)
        else:
            return None

        if format == 'json':
            return json.dumps(requests, indent=2)

        elif format == 'csv':
            if not requests:
                return ""
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=requests[0].keys())
            writer.writeheader()
            writer.writerows(requests)
            return output.getvalue()

        return requests

    # TODO: Add log level filtering (e.g., only errors)
    def add_log_level_filter(self, level):
        """
        Add a filter for log level (e.g., ERROR, WARNING)
        :param level: string
        """
        if not isinstance(level, str):
            raise ValueError("Log level must be a string.")
        self.add_filter(level, is_casesensitive=False, is_regex=False)
    # TODO: Add support for time range filtering

    def parse_args():
        parser = argparse.ArgumentParser(description="Analyze service logs.")

        parser.add_argument("service", help="Name of the service (nginx, apache2, ssh...)")
        parser.add_argument("-f", "--file", help="Path to the log file", default=None)
        parser.add_argument("--output", choices=["json", "csv"], help="Output format", default="json")
        parser.add_argument("--loglevel", help="Log level filter (e.g., ERROR, WARNING)", default=None)
        parser.add_argument("--start", help="Start datetime in ISO format (e.g., 2025-07-11T00:00:00)", default=None)
        parser.add_argument("--end", help="End datetime in ISO format", default=None)

        return parser.parse_args()
    def add_time_range_filter(self, start: datetime, end: datetime):
        """
        Add a filter for a time range (requires datetime parsing)
        :param start: datetime
        :param end: datetime
        """
        def time_filter(line):
            try:
                date_match = re.findall(self.__settings['date_pattern'], line)
                if not date_match:
                    return False
                date_keys = self.__settings['date_keys']
                raw_date = date_match[0]
                months_dict = {v: k for k, v in enumerate(calendar.month_abbr)}
                log_datetime = datetime(
                    int(raw_date[date_keys['year']]) if 'year' in date_keys else datetime.now().year,
                    months_dict[raw_date[date_keys['month']]],
                    int(raw_date[date_keys['day']].strip()),
                    int(raw_date[date_keys['hour']]),
                    int(raw_date[date_keys['minute']]),
                    int(raw_date[date_keys['second']])
                )
                return start <= log_datetime <= end
            except Exception:
                return False

        self.__filters.append({
            'filter_pattern': time_filter,
            'is_casesensitive': True,
            'is_regex': False,
            'is_reverse': False
        })


    # TODO: Add export to CSV
    # def export_to_csv(self, path):
    #     """
    #     Export filtered results to a CSV file
    #     :param path: string
    #     """
    #     pass  # Feature stub
    def export_to_csv(self, path):
        """
    Export filtered results to a CSV file
    :param path: string - full path to write the CSV output
    """
    requests = self.get_requests(format='list')
    if not requests:
        logging.warning("No requests to export.")
        return

    try:
        with open(path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=requests[0].keys())
            writer.writeheader()
            writer.writerows(requests)
        logging.info(f"Exported {len(requests)} records to CSV: {path}")
    except Exception as e:
        logging.error(f"Failed to export CSV to {path}: {e}")

# TODO: Write more tests for edge cases, error handling, and malformed input
