import requests
import time
import json


class Constant:
    Default_Key = ""
    Url_List_File = "url_list.txt"
    Request_Interval = 0.5
    Request_Count_Limit_Per_Key = 9000


def loadUrlList():
    url_list_file = open(Constant.Url_List_File, "r")
    url_list_from_file = url_list_file.readlines()
    print("url count {}".format(len(url_list_from_file)))
    return url_list_from_file


def scanWithWebRisk(api_key_for_web_risk, url_to_scan):
    headers = {
        "key": api_key_for_web_risk,
        "uri": url_to_scan,
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
    }
    resp = requests.get('https://webrisk.googleapis.com/v1/uris:search', headers)

    if resp.status_code != 200:
        print("Web Risk: {} - {}".format(resp.status_code, resp.reason))
        return None

    url_threat = resp.json().get("threat")
    if url_threat is None:
        return None
    else:
        return url_threat.get("threatTypes")


def scanWithSafeBrowsing(api_key_for_safe_browsing, url_to_scan):
    body_raw = '{\
        "client": {\
          "clientId": "Gogolook Co., Ltd.",\
          "clientVersion": "0.0.2"\
        },\
        "threatInfo": {\
          "threatTypes": [\
            "MALWARE",\
            "SOCIAL_ENGINEERING",\
            "UNWANTED_SOFTWARE",\
            "POTENTIALLY_HARMFUL_APPLICATION"\
          ],\
          "platformTypes": [\
            "ANDROID"\
          ],\
          "threatEntryTypes": ["URL"],\
          "threatEntries": [\
          ]\
        }\
      }'
    body_json = json.loads(body_raw)
    threat_info = body_json['threatInfo']
    threat_entries = threat_info['threatEntries']
    threat_entries.append({"url": "{}".format(url_to_scan)})
    params = {"key": api_key_for_safe_browsing}
    resp = requests.post('https://safebrowsing.googleapis.com/v4/threatMatches:find', params=params, json=body_json)

    if resp.status_code != 200:
        print("Safe Browsing: {} - {}".format(resp.status_code, resp.reason))
        return None

    url_threat_list = resp.json().get("matches")
    threat_types = ""

    if url_threat_list is not None and len(url_threat_list) > 0:
        for threat in url_threat_list:
            if threat is not None:
                threat_types += str(threat.get("threatTypes"))

    if threat_types:
        return threat_types
    else:
        return None


# main
total_duration_start = time.monotonic()
url_list = loadUrlList()
key_count = int((len(url_list) / Constant.Request_Count_Limit_Per_Key)) + 1
print("Require key count {}".format(key_count))
api_key_list = []
for i in range(key_count):
    api_key_list.append(input("Enter API key {}: ".format(i + 1)))

web_risk_total_duration = 0
web_risk_found_threat_count = 0
safe_browsing_total_duration = 0
safe_browsing_found_threat_count = 0
api_key = api_key_list.pop()
different_result_url_list = []
for url in url_list:
    index = url_list.index(url)

    # get key
    if index != 0 and index % Constant.Request_Count_Limit_Per_Key == 0:
        api_key = api_key_list.pop()

    print("Use key {}".format(api_key))

    # scan with web risk
    before = time.monotonic()
    web_risk_result = scanWithWebRisk(api_key, url)
    after = time.monotonic()
    web_risk_total_duration = web_risk_total_duration + (after - before)

    if web_risk_result is not None:
        web_risk_found_threat_count += 1

    # scan with safe browsing
    before = time.monotonic()
    safe_browsing_result = scanWithSafeBrowsing(api_key, url)
    after = time.monotonic()
    safe_browsing_total_duration = safe_browsing_total_duration + (after - before)

    if safe_browsing_result is not None:
        safe_browsing_found_threat_count += 1

    # Cache url that has different scan result from web risk and safe browsing
    if web_risk_result != safe_browsing_result:
        different_result_url_list.append(url)

    print("{} - {}".format(index, url))
    time.sleep(Constant.Request_Interval)

# Print result
print(" ========================================================================= ")
print("Scan total cost {}".format(time.monotonic() - total_duration_start))
print("Web Risk API ")
print("    - fount {} threats".format(web_risk_found_threat_count))
print("    - total duration: {}".format(web_risk_total_duration))
print("    - average duration: {}".format(web_risk_total_duration / len(url_list)))

print("Safe Browsing API ")
print("    - fount {} threats".format(safe_browsing_found_threat_count))
print("    - total duration: {}".format(safe_browsing_total_duration))
print("    - average duration: {}".format(safe_browsing_total_duration / len(url_list)))

print("Fount {} different results".format(len(different_result_url_list)))
if len(different_result_url_list) > 0:
    for url in different_result_url_list:
        print("    - {}".format(url))
