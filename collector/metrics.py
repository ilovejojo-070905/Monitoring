"""Phase 5: persists the same numbers that already go into each entity's
in-memory hist[] arrays into metrics_raw, so history survives a server
restart. Deliberately mirrors what each collector already pushes into
hist{} (collector.state.push_cap) rather than inventing a new metric set:
  cpu / mem / disk   -- local & agent devices
  latency            -- ping & snmp devices
  net                -- local & agent (netIn+netOut combined, matches hist.net)
  traffic            -- snmp 'net' category devices (trafficIn+trafficOut, matches hist.traffic)
"""
import time

import storage


def record_entity_metrics(device_id, entity):
    now = int(time.time() * 1000)
    rows = []

    def add(metric, value):
        if value is not None:
            rows.append((device_id, metric, now, float(value)))

    add('cpu', entity.get('cpu'))
    add('mem', entity.get('mem'))
    add('disk', entity.get('disk'))
    add('latency', entity.get('latencyMs'))
    if entity.get('netIn') is not None and entity.get('netOut') is not None:
        add('net', entity['netIn'] + entity['netOut'])
    if entity.get('trafficIn') is not None and entity.get('trafficOut') is not None:
        add('traffic', entity['trafficIn'] + entity['trafficOut'])

    storage.record_metrics(rows)
