from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List


def flow_time(flow):

    '''
    Helper function to retrieve the time of a flow if possible

    'received_at' is added when the flows are processed (in the process_batch
    function in the IngestService class)
    '''

    text = flow.get('received_at')
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def build_60s_series(flows: List[dict]):

    '''
    Builts a dict needed data points for building the table for packets per
    second in the last 60 seconds

    1) Get current time and initialize a list
    2) Create a dict which will contain each (time, packet total) pair.
       First, create dict with x values. 
    3) For each for that occured within the last 60 seconds, take its
       total_packets and add it to the 'y' element of the dict

    '''

    # 1) Get current time and initialize a list
    now = datetime.now().replace(microsecond=0)
    buckets = [] # list of dictionaries

    # 2) Create a dict which will contain each (time, packet total) pair.
    # First, create dict with x values. 
    for offset in range(59, -1, -1):
        ts = now - timedelta(seconds=offset)
        buckets.append({'x': ts.strftime('%H:%M:%S'), 'y': 0})
    label_index = {item['x']: item for item in buckets} #reference to dicts in bucket
    # so this does now {ts.strftime : {'x' : ts.strftime, 'y': 0}}
    # 3) For each for that occured within the last 60 seconds, take its
    # total_packets and add it to the 'y' element of the dict
    for flow in flows:
        ts = flow_time(flow)
        if ts and ts >= now - timedelta(seconds=60): # within the last 60 seconds
            key = ts.replace(microsecond=0).strftime('%H:%M:%S') # make key for searching
            if key in label_index:
                label_index[key]['y'] += int(flow.get('total_packets', 0)) # ass total packets to y
    return buckets


def build_minute_series(flows: List[dict]):

    '''
    Builts a dict needed data points for building the table for packets per
    minute in the last 60 minutes.
    Follows the same logic as the 60 second chart.
    '''

    now = datetime.now().replace(second=0, microsecond=0)
    buckets = []
    for offset in range(59, -1, -1):
        ts = now - timedelta(minutes=offset)
        buckets.append({'x': ts.strftime('%H:%M'), 'y': 0})
    label_index = {item['x']: item for item in buckets}
    for flow in flows:
        ts = flow_time(flow)
        if ts and ts >= now - timedelta(minutes=59):
            key = ts.replace(second=0, microsecond=0).strftime('%H:%M')
            if key in label_index:
                label_index[key]['y'] += int(flow.get('total_packets', 0))
    return buckets


def build_24h_series(flows: List[dict]):

    '''
    Builts a dict needed data points for building the table for packets per
    hour in the last 24 hours.
    Follows the same logic as the 60 second and 60 minute chart.
    '''

    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    buckets = []
    for offset in range(23, -1, -1):
        ts = now - timedelta(hours=offset)
        buckets.append({'x': ts.strftime('%m-%d %H:00'), 'y': 0})
    label_index = {item['x']: item for item in buckets}
    for flow in flows:
        ts = flow_time(flow)
        if ts and ts >= now - timedelta(hours=23):
            key = ts.replace(minute=0, second=0, microsecond=0).strftime('%m-%d %H:00')
            if key in label_index:
                label_index[key]['y'] += int(flow.get('total_packets', 0))
    return buckets


def build_day_series(flows: List[dict], days: int = 30):

    '''
    Builts a dict needed data points for building the table for packets per
    day for the last 30 days.
    Follows the same logic as the other charts.
    '''
    now = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    buckets = []
    for offset in range(days - 1, -1, -1):
        ts = now - timedelta(days=offset)
        buckets.append({'x': ts.strftime('%Y-%m-%d'), 'y': 0})
    label_index = {item['x']: item for item in buckets}
    for flow in flows:
        ts = flow_time(flow)
        if ts and ts >= now - timedelta(days=days - 1):
            key = ts.strftime('%Y-%m-%d')
            if key in label_index:
                label_index[key]['y'] += int(flow.get('total_packets', 0))
    return buckets


def build_attack_counts(flows: List[dict]) -> Dict[str, int]:

    '''
    Builds dictionary with data for graph containing counts of each
    attack type.

    1) Get a count of all different attack labels for attack counts
    2) Ensure that there is a count for benign even if there are none
    '''

    # unknown as counter default
    # 1) Get a count of all different attack labels for attack counts
    counter = Counter(flow.get('attack_label', 'unknown') for flow in flows)

    # 2) Ensure that there is a count for benign even if there are none
    if 'benign' not in counter:
        counter['benign'] = 0
    return dict(counter)


# returns flows inside a date range

def filter_flows_by_range(flows: List[dict], start_date: str | None, end_date: str | None):

    '''
    Get a list with flows within a range specified

    1) Handle start date and end date
    2) Store flows with date within the range specified in the client
    '''

    # 1) Handle start date and end date
    start_dt = None
    end_dt = None

    if start_date:
        start_dt = datetime.fromisoformat(start_date).replace(hour=0, minute=0, second=0, microsecond=0)
    if end_date:
        end_dt = datetime.fromisoformat(end_date).replace(hour=23, minute=59, second=59, microsecond=999999)


    # 2) Store flows with date within the range specified in the client
    filtered = []
    for flow in flows:
        ts = flow_time(flow)
        if not ts:
            continue
        if start_dt and ts < start_dt:
            continue
        if end_dt and ts > end_dt:
            continue
        filtered.append(flow)
    return filtered


# returns graph info for a report page

def build_report_bundle(flows: List[dict], start_date: str | None = None, end_date: str | None = None):

    '''
    Returns all data for graphs for the report page. This includes all 5 graphs
    AND grouped individual days

    1) First, group flows by date
    2) Get packets per hour in the range of 24 hours for every individual
    existing day. This is used for the report page. Follows similar logic
    to the other functions.
    3) Return all the data needed for the report.


    '''

    # 1) First, group flows by date
    selected = filter_flows_by_range(flows, start_date, end_date)
    grouped = defaultdict(list)
    for flow in selected:
        ts = flow_time(flow)
        if ts:
            grouped[ts.strftime('%Y-%m-%d')].append(flow)

    # 2) Get packets per hour in the range of 24 hours for every individual
    # existing day. This is used for the report page. Follows similar logic
    # to the other functions.
    individual_days = []
    for day in sorted(grouped.keys()):
        day_flows = grouped[day]
        hour_map = defaultdict(int)
        for flow in day_flows:
            ts = flow_time(flow)
            if ts:
                hour_map[ts.strftime('%H:00')] += int(flow.get('total_packets', 0))
        hour_series = [{'x': f'{hour:02d}:00', 'y': hour_map.get(f'{hour:02d}:00', 0)} for hour in range(24)]
        individual_days.append({
            'day': day,
            'counts': build_attack_counts(day_flows),
            'hour_series': hour_series,
            'flows': len(day_flows),
        })

    # 3) Return all the data needed for the report.

    return {
        'selected_flows': selected,
        'per_second': build_60s_series(selected),
        'per_minute': build_minute_series(selected),
        'per_hour': build_24h_series(selected),
        'per_day': build_day_series(selected),
        'attack_counts': build_attack_counts(selected),
        'individual_days': individual_days,
    }
