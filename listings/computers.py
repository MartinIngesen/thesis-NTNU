import json

computers = {}

def convertEvents(sysmon):
    for event in sysmon:
        if "Microsoft-Windows-Sysmon" in event:
            event = json.loads(event)

            if "computer_name" in event:
                hostname = event["computer_name"]
            elif "winlog" in event:
                hostname = event["winlog"]["computer_name"]
            
            if hostname not in computers:
                computers[hostname] = 1
            
with open('./caldera_attack_evals_round1_day1_2019-10-20201108.json', 'r') as sysmon:
    convertEvents(sysmon)

with open('./empire_apt3_2019-05-14223117.json', 'r') as sysmon:
    convertEvents(sysmon)

print(f"There are {len(computers)} in total:")
for computer in computers:
    print(computer)