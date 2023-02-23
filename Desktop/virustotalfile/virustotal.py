import requests
import json
import time


indicators = [
    "google.com",
    "myetherevvalliet.com"
]

apiKey = '4be7ba27c763b11f3e751b0e48ab669811d7c90cfdccbef75e41c0fb9546623b'

url = 'https://www.virustotal.com/vtapi/v2/url/report'

for site in indicators:
    params = {'apikey': apiKey, 'resource': site}
    response = requests.get(url, params=params)
    response_json = json.loads(response.content)

    if response_json['positives']<= 0:
        with open('vt_results.txt', 'a') as vt:
            vt.write(site) and vt.write(' -\tNOT MALICIOUS\n')

    elif 1 >= response_json['positives'] >= 3:
        with open('vt_results.txt', 'a') as vt:
            vt.write(site) and vt.write(' -\tMAYBE MALICIOUS\n')

    elif response_json['positives'] >= 4:
        with open('vt_results.txt', 'a') as vt:
            vt.write(site) and vt.write(' -\tMALICIOUS\n')

    else:
        print('url does exist')

    time.sleep(15)