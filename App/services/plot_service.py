from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List

# creating axis for line graph that shows the last 60 seconds of activity
def build_60s_series(flows: List[dict]):
    now = datetime.now()
    buckets = []
    # create x values of the last 60 seconds
    for offset in range(59, -1, -1):
        start = now - timedelta(seconds=offset)

        #values
        label = start.strftime('%H:%M:%S')
        buckets.append({'x': label, 'y': 0})
    label_index = {item['x']: item for item in buckets}

    # create y values
    for flow in flows:
        try:
            # take datetime value from each flow
            ts = datetime.fromisoformat(flow['received_at'])
            if ts >= now - timedelta(seconds=60):
                key = ts.strftime('%H:%M:%S')
                # if the time of the flow matches that of x value that already exist in label_index, add it to be used for the y axis
                # this will be done for all flows in the dataset
                # the same process is done for the 24 hour dataset
                if key in label_index:
                    label_index[key]['y'] += int(flow.get('total_packets', 0))
        except Exception:
            continue
    return buckets

# creating axis for line graph that shows the last 60 seconds of activity
def build_24h_series(flows: List[dict]):
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    buckets = []
    for offset in range(23, -1, -1):
        ts = now - timedelta(hours=offset)
        label = ts.strftime('%m-%d %H:00')
        buckets.append({'x': label, 'y': 0})
    label_index = {item['x']: item for item in buckets}
    for flow in flows:
        try:
            ts = datetime.fromisoformat(flow['received_at']).replace(minute=0, second=0, microsecond=0)
            if ts >= now - timedelta(hours=23):
                key = ts.strftime('%m-%d %H:00')
                if key in label_index:
                    label_index[key]['y'] += int(flow.get('total_packets', 0))
        except Exception:
            continue
    return buckets


def build_attack_counts(flows: List[dict]) -> Dict[str, int]:
    # get the labels
    counter = Counter(flow.get('attack_label', 'unknown') for flow in flows)
    
    # incase there is no flow classified as benign, force benign = 0 in the dict
    if 'benign' not in counter:
        counter['benign'] = 0
    return dict(counter)
