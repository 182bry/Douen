from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List


def flow_time(flow):

    '''
    Helper function to retrieve the time of a flow if possible
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
    '''

    now = datetime.now().replace(microsecond=0)
    buckets = []
    for offset in range(59, -1, -1):
        ts = now - timedelta(seconds=offset)
        buckets.append({'x': ts.strftime('%H:%M:%S'), 'y': 0})
    label_index = {item['x']: item for item in buckets}
    for flow in flows:
        ts = flow_time(flow)
        if ts and ts >= now - timedelta(seconds=60):
            key = ts.replace(microsecond=0).strftime('%H:%M:%S')
            if key in label_index:
                label_index[key]['y'] += int(flow.get('total_packets', 0))
    return buckets


def build_poll_activity_series(flows: List[dict], poll_seconds=3, divisions: int = 50):

    '''
    Builds packet activity points based on the current polling interval.
    '''

    try:
        poll_seconds = float(poll_seconds)
    except Exception:
        poll_seconds = 3.0
    if poll_seconds <= 0:
        poll_seconds = 3.0

    now = datetime.now().replace(microsecond=0)
    buckets = []
    for offset in range(divisions - 1, -1, -1):
        ts = now - timedelta(seconds=offset * poll_seconds)
        buckets.append({'x': ts.strftime('%H:%M:%S'), 'y': 0})

    oldest = now - timedelta(seconds=(divisions - 1) * poll_seconds)
    for flow in flows:
        ts = flow_time(flow)
        if not ts or ts < oldest or ts > now:
            continue
        diff = (now - ts).total_seconds()
        bucket_from_now = int(diff // poll_seconds)
        index = divisions - 1 - bucket_from_now
        if 0 <= index < len(buckets):
            buckets[index]['y'] += int(flow.get('total_packets', 0))
    return buckets


def build_minute_series(flows: List[dict]):

    '''
    Builts a dict needed data points for building the table for packets per
    minute in the last 60 minutes.
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
    '''

    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    buckets = []
    for offset in range(23, -1, -1):
        ts = now - timedelta(hours=offset)
        buckets.append({'x': ts.strftime('%H:00'), 'y': 0})
    label_index = {item['x']: item for item in buckets}
    for flow in flows:
        ts = flow_time(flow)
        if ts and ts >= now - timedelta(hours=23):
            key = ts.replace(minute=0, second=0, microsecond=0).strftime('%H:00')
            if key in label_index:
                label_index[key]['y'] += int(flow.get('total_packets', 0))
    return buckets


def build_day_series(flows: List[dict], days: int = 7):

    '''
    Builts a dict needed data points for building the table for packets per
    day.
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
    '''

    labels = []
    for flow in flows:
        label = str(flow.get('attack_label', 'unknown'))
        if label.upper() == 'BENIGN':
            label = 'benign'
        labels.append(label)
    counter = Counter(labels)
    if 'benign' not in counter:
        counter['benign'] = 0
    return dict(counter)


def filter_flows_by_range(flows: List[dict], start_date: str | None, end_date: str | None):

    '''
    Get a list with flows within a range specified
    '''

    start_dt = None
    end_dt = None

    if start_date:
        start_dt = datetime.fromisoformat(start_date).replace(hour=0, minute=0, second=0, microsecond=0)
    if end_date:
        end_dt = datetime.fromisoformat(end_date).replace(hour=23, minute=59, second=59, microsecond=999999)

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


def build_report_bundle(flows: List[dict], start_date: str | None = None, end_date: str | None = None, poll_seconds=3):

    '''
    Returns all data for graphs for the report page.
    '''

    selected = filter_flows_by_range(flows, start_date, end_date)
    grouped = defaultdict(list)
    for flow in selected:
        ts = flow_time(flow)
        if ts:
            grouped[ts.strftime('%Y-%m-%d')].append(flow)

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
            'flows': len(day_flows),
            'counts': build_attack_counts(day_flows),
            'hour_series': hour_series,
        })

    return {
        'selected_flows': selected,
        'packet_activity': build_poll_activity_series(selected, poll_seconds),
        'per_second': build_60s_series(selected),
        'per_minute': build_minute_series(selected),
        'per_hour': build_24h_series(selected),
        'per_day': build_day_series(selected),
        'attack_counts': build_attack_counts(selected),
        'individual_days': individual_days,
    }
