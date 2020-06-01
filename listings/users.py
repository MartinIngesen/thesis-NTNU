import json

users = {}

def convertEvents(sysmon):
    for event in sysmon:
        if "Microsoft-Windows-Sysmon" in event:
            event = json.loads(event)

            if "winlog" in event:
                if "event_data" in event["winlog"]:
                    if "User" in event["winlog"]["event_data"]:
                        user = event["winlog"]["event_data"]["User"]
                        if user not in m:
                            users[user] = 1
            
with open('./caldera_attack_evals_round1_day1_2019-10-20201108.json', 'r') as sysmon:
    convertEvents(sysmon)

with open('./empire_apt3_2019-05-14223117.json', 'r') as sysmon:
    convertEvents(sysmon)

print(f"There are {len(users)} in total:")
for user in users:
    print(user)