import json
from datetime import datetime

epoch = datetime.utcfromtimestamp(0)

depth = 9 # 10s intervals
m = {}

def unix_time_millis(datetime):
    return str((datetime - epoch).total_seconds() * 1000.0).replace(".0", "")

def convertEvents(sysmon):
    for event in sysmon:
        if "Microsoft-Windows-Sysmon" in event:
            event = json.loads(event)
            timestamp = event['@timestamp']
            parsed = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ")
            millis = unix_time_millis(parsed)
            top = millis[:depth]

            if top in m:
                m[top] += 1
            else:
                m[top] = 1
            
with open('./caldera_attack_evals_round1_day1_2019-10-20201108.json', 'r') as sysmon:
    convertEvents(sysmon)

with open('./empire_apt3_2019-05-14223117.json', 'r') as sysmon:
    convertEvents(sysmon)

for x in m:
    print(f"({x},{m[x]})")