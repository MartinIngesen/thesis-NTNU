import json

def convertEvents(sysmon):
    for event in sysmon:
        if "Microsoft-Windows-Sysmon" in event:
            event = json.loads(event)
            
            m = event["message"]
            m = m.replace("\n", "  ")
            
            if "computer_name" in event:
                h = event["computer_name"]
            elif "winlog" in event:
                h = event["winlog"]["computer_name"]
            else:
                h = "NOHOSTNAME"

            x = f"<14>Jan 01 00:00:00 {h} Microsoft-Windows-Sysmon[2092]: {m}"
            print(x)

with open('./caldera_attack_evals_round1_day1_2019-10-20201108.json','r') as sysmon:
    convertEvents(sysmon)

with open('./empire_apt3_2019-05-14223117.json','r') as sysmon:
    convertEvents(sysmon)