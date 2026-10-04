"""Centralized CPU/memory/disk threshold resolution + evaluation (2-2).

Before this, "is this reading warn/crit" was decided three different ways:
hardcoded inline in agent_collector.record_report, hardcoded inline
(duplicated) in local_collector.sample_local, and not at all for SNMP-polled
devices (switches/routers/UPS never got a resource-threshold incident no
matter how high their SNMP-reported CPU went -- only reachability did).
Every caller now goes through resolve_thresholds() + evaluate_resource()
here instead, so there's exactly one place that knows what "90%" means for
a given device.

Precedence (highest wins, per-field): device override (devices.fields.
thresholds) > group default (device_groups.thresholds, by the device's
`group` field) > global default (settings['thresholds_global']) > the
hardcoded fallback below, which is simply today's old behavior preserved as
the floor -- "설정이 없는 장비는 기존 전역 임계치를 적용한다".
"""
import time

import storage
from collector import state

FALLBACK_THRESHOLDS = {
    'cpu': {'warn': 75, 'crit': 90},
    'mem': {'warn': 80, 'crit': 92},
    'disk': {'warn': 80, 'crit': 92},
    'sustainedSec': 0,  # 0 = fire immediately, i.e. unchanged from pre-2-2 behavior unless configured
}

_RANK = {'good': 0, 'warn': 1, 'crit': 2}

# device_id -> {'cpu': first-over-threshold ts_ms or None, 'mem': ..., 'disk': ...}
# In-memory only -- a restart just resets the sustain window, which is fine
# (worst case: one extra poll's wait before the next alert after a restart).
_OVER_SINCE = {}

# device_id -> the last incident_status evaluate_resource() actually
# returned (NOT the same as entity['status']/display_status -- see
# evaluate_resource's docstring for why these two can't share one prev-
# status tracker without a transition bug around the sustain gate).
_PREV_INCIDENT_STATUS = {}


def get_global_thresholds():
    raw = storage.get_setting('thresholds_global')
    out = {**FALLBACK_THRESHOLDS}
    if raw:
        import json
        try:
            out.update(json.loads(raw))
        except Exception:
            pass
    return out


def set_global_thresholds(data):
    import json
    storage.set_setting('thresholds_global', json.dumps(data))


def _apply_override(base, override):
    if not override:
        return
    for metric in ('cpu', 'mem', 'disk'):
        if metric in override and override[metric]:
            base[metric] = dict(override[metric])
    if 'sustainedSec' in override and override['sustainedSec'] is not None:
        base['sustainedSec'] = override['sustainedSec']


def resolve_thresholds(device_row, global_thresholds=None, groups_cache=None):
    """device_row: a dict as returned by storage.load_device(s) -- needs
    ['fields'] already parsed (it always is, from those two functions).
    Returns the fully-resolved {cpu:{warn,crit}, mem:{...}, disk:{...},
    sustainedSec} after layering device -> group -> global, field by field
    (a device overriding only `cpu` still inherits mem/disk from whichever
    of its group/global has them).

    global_thresholds/groups_cache let a caller resolving many devices at
    once (serialize_device() over a whole /api/state poll) pass in a single
    pre-fetched global-settings read and {group_name: group_row} map instead
    of this function re-querying both from SQLite once per device, every
    ~2.2s poll cycle. Collector call sites (one device per call) still just
    omit them and pay one cheap query each, same as before this existed."""
    result = dict(global_thresholds) if global_thresholds is not None else get_global_thresholds()
    fields = device_row.get('fields') or {}
    group_name = fields.get('group')
    if group_name:
        group = groups_cache.get(group_name) if groups_cache is not None else storage.get_device_group(group_name)
        if group:
            _apply_override(result, group.get('thresholds'))
    _apply_override(result, fields.get('thresholds'))
    return result


def _level(value, bounds):
    if value is None:
        return 'good'
    if value >= bounds['crit']:
        return 'crit'
    if value >= bounds['warn']:
        return 'warn'
    return 'good'


def _check_sustained(device_id, metric, is_over, sustained_sec, now_ms):
    bucket = _OVER_SINCE.setdefault(device_id, {})
    if not is_over:
        bucket[metric] = None
        return False
    if bucket.get(metric) is None:
        bucket[metric] = now_ms
    if sustained_sec <= 0:
        return True
    return (now_ms - bucket[metric]) >= sustained_sec * 1000


def evaluate_resource(device_id, cpu, mem, disk, thresholds_dict, now_ms=None):
    """Returns (display_status, incident_event). display_status is the
    instantaneous good/warn/crit for the UI (status pill, topology color,
    KPI counts) -- unchanged from before 2-2, still reacts the instant a
    reading crosses the line.

    incident_event is None (nothing to report this poll), or a
    ('escalate', new_status) / ('recover', 'good') tuple the caller should
    turn into an add_incident() call -- this function does the *sustained*
    incident-status transition tracking itself (device_id -> last incident
    status, separate from entity['status']/display_status) rather than
    handing back a bare status for the caller to rank-compare against its
    own prev_status: that status is the raw instantaneous one, which can
    already equal the final incident status well before the sustain gate
    is satisfied (the instant a reading crosses the line), making a naive
    "did it get worse than prev display status" comparison miss the actual
    transition once the gate finally opens. Tracking it here, against what
    this function itself last returned, is the only way to get that right.
    """
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    cpu_lvl = _level(cpu, thresholds_dict['cpu'])
    mem_lvl = _level(mem, thresholds_dict['mem'])
    disk_lvl = _level(disk, thresholds_dict['disk'])
    display_status = max((cpu_lvl, mem_lvl, disk_lvl), key=lambda s: _RANK[s])

    sustained_sec = thresholds_dict.get('sustainedSec', 0)
    levels = {'cpu': cpu_lvl, 'mem': mem_lvl, 'disk': disk_lvl}
    sustained_levels = [
        lvl for metric, lvl in levels.items()
        if _check_sustained(device_id, metric, lvl != 'good', sustained_sec, now_ms)
    ]
    incident_status = max(sustained_levels, key=lambda s: _RANK[s]) if sustained_levels else 'good'

    prev_incident_status = _PREV_INCIDENT_STATUS.get(device_id, 'good')
    event = None
    if _RANK[incident_status] > _RANK[prev_incident_status]:
        event = ('escalate', incident_status)
    elif incident_status == 'good' and prev_incident_status != 'good':
        event = ('recover', 'good')
    _PREV_INCIDENT_STATUS[device_id] = incident_status
    return display_status, event


def worse(a, b):
    """The more severe of two good/warn/crit statuses -- e.g. an SNMP device
    that's reachable (status='good' so far) but over its CPU threshold
    should end up 'warn'/'crit' overall, not have the resource reading
    silently ignored because reachability alone said 'good'."""
    return a if _RANK[a] >= _RANK[b] else b


def clear_sustain_state(device_id):
    """Called when a device is deleted -- nothing catastrophic if this is
    skipped (the dict entry is small and keyed by an id that'll never
    recur), but no reason to leak it either."""
    _OVER_SINCE.pop(device_id, None)
    _PREV_INCIDENT_STATUS.pop(device_id, None)
