import json

def convertEvents(sysmon):
    for event in sysmon:
        if "Microsoft-Windows-Sysmon" in event:
            event = json.loads(event)
            
            message = event["message"]
            message = message.replace("\n", "  ")
            
            if "computer_name" in event:
                hostname = event["computer_name"]
            elif "winlog" in event:
                hostname = event["winlog"]["computer_name"]
            else:
                hostname = "NOHOSTNAME"

            x = f"<14>Jan 01 00:00:00 {hostname} Microsoft-Windows-Sysmon[2092]: {message}"
            print(x)

with open('./apt3/caldera_attack_evals_round1_day1_2019-10-20201108.json', 'r') as sysmon:
    convertEvents(sysmon)

with open('./apt3/empire_apt3_2019-05-14223117.json', 'r') as sysmon:
    convertEvents(sysmon)