"""2-3: 점검창 자동화 -- schedule definitions (maintenance_windows) that drive
devices.maintenance_* automatically, on top of the existing manual per-device
toggle (drawer's "유지보수 시작/해제" button) rather than replacing it.

tick() runs every 60s from scheduler.py's own job pool (no new thread/
scheduler -- same reasoning as flow_listener.flush). For each enabled
window, it resolves the window's target devices (a single device, or every
device currently carrying that group name in fields.group -- the same
dynamic-membership resolution groups use everywhere else in this app, not a
stored roster), and reconciles each device's live maintenance state against
"should this window be active right now":

  - window active now, device not currently owned by this window
      -> turn maintenance on, stamp maintenance_window_id = this window's id
  - window not active now, device currently owned by this window
      -> turn maintenance back off

A device whose maintenance_window_id is NULL (manual toggle, or never
touched by a window) is left alone by every window that doesn't claim it
this tick -- see storage.set_maintenance()'s docstring for the full
ownership rule, including the one deliberate edge case: if an operator
manually cancels maintenance early while a window is still active, the next
tick reclaims it (the window's job is to cover its whole configured period;
turning it off for good means disabling/deleting the window itself, not
fighting the schedule tick by tick).
"""
from datetime import datetime

import storage

_HHMM_TO_MINUTES = lambda s: int(s[:2]) * 60 + int(s[3:5])  # 'HH:MM' -> minutes since midnight


def resolve_target_device_ids(window):
    if window['scope'] == 'device':
        d = storage.load_device(window['scope_id'])
        return [d['id']] if d else []
    # scope == 'group'
    return [d['id'] for d in storage.load_devices() if (d.get('fields') or {}).get('group') == window['scope_id']]


def window_occurrence_bounds(window, now_dt):
    """Returns (is_active_now, occurrence_start_ms, occurrence_end_ms) for
    this window's CURRENT occurrence (today's slot, for a weekly window) --
    the ms bounds are stored on the device as maintenance_start/end so the
    existing in_maintenance() window check (and the drawer's display of
    them) works unchanged regardless of which kind scheduled it."""
    if window['kind'] == 'once':
        start, end = window.get('start_at'), window.get('end_at')
        if start is None or end is None:
            return False, None, None
        now_ms = int(now_dt.timestamp() * 1000)
        return (start <= now_ms <= end), start, end
    # kind == 'weekly'
    if window.get('weekday') is None or not window.get('start_time') or not window.get('end_time'):
        return False, None, None
    if now_dt.weekday() != window['weekday']:
        return False, None, None
    now_minutes = now_dt.hour * 60 + now_dt.minute
    start_m = _HHMM_TO_MINUTES(window['start_time'])
    end_m = _HHMM_TO_MINUTES(window['end_time'])
    # No overnight-crossing support (start > end would mean "wraps past
    # midnight") -- validation.py rejects that at creation time, so this
    # only ever has to handle a same-day slot.
    if not (start_m <= now_minutes <= end_m):
        return False, None, None
    midnight = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    occ_start = int((midnight.timestamp() + start_m * 60) * 1000)
    occ_end = int((midnight.timestamp() + end_m * 60) * 1000)
    return True, occ_start, occ_end


def tick():
    now_dt = datetime.now()
    windows = [w for w in storage.load_maintenance_windows() if w.get('enabled')]
    devices_by_id = {d['id']: d for d in storage.load_devices()}
    for window in windows:
        is_active, occ_start, occ_end = window_occurrence_bounds(window, now_dt)
        for device_id in resolve_target_device_ids(window):
            device_row = devices_by_id.get(device_id)
            if not device_row:
                continue
            owned_by_this = device_row.get('maintenance_window_id') == window['id']
            if is_active and not owned_by_this:
                storage.set_maintenance(
                    device_id, True, start=occ_start, end=occ_end, reason=window.get('reason') or '예약된 점검',
                    window_id=window['id'], started_by='scheduler')
            elif not is_active and owned_by_this:
                storage.set_maintenance(device_id, False, window_id=None, started_by='scheduler')
