"""3-1: 가동률 및 SLA 리포트 -- uptime/downtime, MTTR, MTBF computation.

가동률 산정 기준 (uptime calculation policy -- stated explicitly per the
ticket's own requirement to document this):

  measured_time = period_duration - maintenance_time - collection_gap_time
  uptime%       = (measured_time - downtime_time) / measured_time * 100

- **measurement period**: an explicit [start_ms, end_ms) the caller passes
  in (a day/week/month bucket, or any custom range) -- there is no implicit
  "since the device was registered" default.
- **예정 점검 시간 (scheduled maintenance)**: excluded from BOTH the
  numerator and denominator entirely, via maintenance_log (storage.
  load_maintenance_log_range) -- time spent in a planned maintenance window
  counts as neither "up" nor "down". This is standard SLA practice: a
  planned outage you caused on purpose shouldn't inflate (if ignored and
  presumed "up") or deflate (if counted as "down") the number.
- **수집 데이터 누락 (collection gaps)**: also excluded from both numerator
  and denominator, via event_type='COLLECTION_ERROR' incidents (storage.
  load_incidents_in_range) -- the collector itself failed to run (a bug, a
  crashed dependency), which is categorically different information from
  "the device was actually unreachable" (event_type='REACHABILITY') and
  must never be silently counted as downtime just because the device
  *looked* down from a missing data point. These show up in the report as
  a separate "데이터 누락 시간" figure, never folded into uptime%.
- **실제 장애 (real downtime)**: event_type='REACHABILITY' incidents whose
  severity is in the configured downtime_severities (storage.
  get_sla_settings_public, default both warn+crit). An incident recorded
  with during_maintenance=1 is NOT specially filtered here -- it doesn't
  need to be, because its interval already falls inside a maintenance_log
  window by construction (storage.in_maintenance() is what set that flag
  in the first place), so subtracting maintenance intervals from the
  downtime intervals (see _subtract below) already removes it.
"""
import time

import storage

DAY_MS = 86400 * 1000


def _clip(intervals, start, end):
    out = []
    for s, e in intervals:
        s2, e2 = max(s, start), min(e, end)
        if s2 < e2:
            out.append((s2, e2))
    return out


def _merge(intervals):
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged = [list(intervals[0])]
    for s, e in intervals[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return [(s, e) for s, e in merged]


def _total(intervals):
    return sum(e - s for s, e in intervals)


def _subtract(a_intervals, b_intervals):
    """a - b, where a and b are each already merged/sorted (e, e) lists.
    Standard sweep: walk each `a` interval, carving out any `b` interval
    that overlaps it."""
    out = []
    for s, e in a_intervals:
        cur = s
        for bs, be in b_intervals:
            if be <= cur:
                continue
            if bs >= e:
                break
            if bs > cur:
                out.append((cur, min(bs, e)))
            cur = max(cur, be)
            if cur >= e:
                break
        if cur < e:
            out.append((cur, e))
    return out


def device_uptime_report(device_row, start_ms, end_ms):
    """device_row: as returned by storage.load_device(s) (needs ['id']).
    Returns a dict with the uptime%, the time breakdown that explains it,
    and the per-incident detail list the UI/reports render as a table."""
    device_id = device_row['id']
    period_ms = max(end_ms - start_ms, 0)

    maint_rows = storage.load_maintenance_log_range(device_id, start_ms, end_ms)
    maint_intervals = _merge(_clip(
        [(m['started_at'], m['ended_at'] if m['ended_at'] is not None else end_ms) for m in maint_rows],
        start_ms, end_ms))
    maintenance_ms = _total(maint_intervals)

    gap_rows = storage.load_incidents_in_range(device_id, ['COLLECTION_ERROR'], start_ms, end_ms)
    gap_intervals = _merge(_clip(
        [(i['first_occurred_at'], i['resolved_at'] if i['resolved_at'] is not None else end_ms) for i in gap_rows],
        start_ms, end_ms))
    gap_ms = _total(gap_intervals)

    excluded_intervals = _merge(maint_intervals + gap_intervals)
    measured_ms = max(period_ms - _total(excluded_intervals), 0)

    downtime_severities = set(storage.get_sla_settings_public()['downtimeSeverities'])
    down_rows = storage.load_incidents_in_range(device_id, ['REACHABILITY'], start_ms, end_ms)
    down_rows = [i for i in down_rows if i['severity'] in downtime_severities]
    down_raw = _clip(
        [(i['first_occurred_at'], i['resolved_at'] if i['resolved_at'] is not None else end_ms) for i in down_rows],
        start_ms, end_ms)
    down_intervals = _subtract(_merge(down_raw), excluded_intervals)
    downtime_ms = _total(down_intervals)

    uptime_pct = 100.0 if measured_ms <= 0 else max(0.0, min(100.0, (measured_ms - downtime_ms) / measured_ms * 100))

    # 장애 발생 횟수/MTTR: counted from the (not-yet-maintenance-subtracted)
    # incident rows themselves, by whether first_occurred_at falls in this
    # period -- a 15-minute outage that straddles a maintenance window at
    # its tail end is still one real failure that started outside it.
    failures = [i for i in down_rows if start_ms <= i['first_occurred_at'] < end_ms]
    resolved_durations = [i['resolved_at'] - i['first_occurred_at'] for i in failures if i['resolved_at']]
    mttr_ms = (sum(resolved_durations) / len(resolved_durations)) if resolved_durations else None
    mtbf_ms = (measured_ms / len(failures)) if failures else None

    return {
        'deviceId': device_id, 'deviceName': device_row.get('name'),
        'periodStart': start_ms, 'periodEnd': end_ms,
        'uptimePct': round(uptime_pct, 3),
        'measuredMs': measured_ms, 'downtimeMs': downtime_ms,
        'maintenanceMs': maintenance_ms, 'collectionGapMs': gap_ms,
        'failureCount': len(failures), 'mttrMs': mttr_ms, 'mtbfMs': mtbf_ms,
        'incidents': [{
            'id': i['id'], 'severity': i['severity'], 'message': i['message'],
            'firstOccurredAt': i['first_occurred_at'],
            'resolvedAt': i['resolved_at'],
            'durationMs': (i['resolved_at'] or end_ms) - i['first_occurred_at'],
            'ongoing': i['resolved_at'] is None,
        } for i in down_rows],
    }


def group_uptime_report(group_name, member_devices, start_ms, end_ms):
    """member_devices: device rows already filtered to this group (caller's
    job -- see server.py, which resolves fields.group membership the same
    way every other group feature in this app does). Aggregates by summing
    time across all members rather than averaging each device's percentage,
    so one device with much more measured time (e.g. newly registered
    mid-period) doesn't get equal weight to one measured the whole period."""
    per_device = [device_uptime_report(d, start_ms, end_ms) for d in member_devices]
    total_measured = sum(r['measuredMs'] for r in per_device)
    total_downtime = sum(r['downtimeMs'] for r in per_device)
    uptime_pct = 100.0 if total_measured <= 0 else max(0.0, min(100.0, (total_measured - total_downtime) / total_measured * 100))
    failures = sum(r['failureCount'] for r in per_device)
    all_mttr_samples = [d['durationMs'] for r in per_device for d in r['incidents'] if not d['ongoing']]
    mttr_ms = (sum(all_mttr_samples) / len(all_mttr_samples)) if all_mttr_samples else None
    mtbf_ms = (total_measured / failures) if failures else None
    return {
        'group': group_name, 'periodStart': start_ms, 'periodEnd': end_ms,
        'uptimePct': round(uptime_pct, 3),
        'measuredMs': total_measured, 'downtimeMs': total_downtime,
        'maintenanceMs': sum(r['maintenanceMs'] for r in per_device),
        'collectionGapMs': sum(r['collectionGapMs'] for r in per_device),
        'failureCount': failures, 'mttrMs': mttr_ms, 'mtbfMs': mtbf_ms,
        'deviceReports': per_device,
    }


def _bucket_bounds(start_ms, end_ms, granularity):
    """Yields (bucket_start, bucket_end) pairs covering [start_ms, end_ms)
    at day/week/month granularity, in LOCAL time (time.localtime) so a
    '일별' bucket lines up with a calendar day for whoever's reading the
    report, not a UTC day."""
    import datetime
    start_dt = datetime.datetime.fromtimestamp(start_ms / 1000)
    end_dt = datetime.datetime.fromtimestamp(end_ms / 1000)
    if granularity == 'day':
        cur = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        while cur < end_dt:
            nxt = cur + datetime.timedelta(days=1)
            yield int(cur.timestamp() * 1000), int(nxt.timestamp() * 1000)
            cur = nxt
    elif granularity == 'week':
        cur = (start_dt - datetime.timedelta(days=start_dt.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        while cur < end_dt:
            nxt = cur + datetime.timedelta(days=7)
            yield int(cur.timestamp() * 1000), int(nxt.timestamp() * 1000)
            cur = nxt
    elif granularity == 'month':
        cur = start_dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        while cur < end_dt:
            nxt = (cur.replace(day=28) + datetime.timedelta(days=4)).replace(day=1)
            yield int(cur.timestamp() * 1000), int(nxt.timestamp() * 1000)
            cur = nxt
    else:
        raise ValueError('granularity must be day, week, or month')


def bucketed_device_report(device_row, start_ms, end_ms, granularity):
    """One device_uptime_report() per day/week/month bucket within
    [start_ms, end_ms) -- each bucket clipped to the overall range, so a
    partial first/last bucket is measured over only the days actually
    requested, not padded out to a full calendar period."""
    out = []
    for b_start, b_end in _bucket_bounds(start_ms, end_ms, granularity):
        s, e = max(b_start, start_ms), min(b_end, end_ms)
        if s >= e:
            continue
        out.append(device_uptime_report(device_row, s, e))
    return out
