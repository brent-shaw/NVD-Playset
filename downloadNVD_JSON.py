import requests
import re
import os
import zipfile

r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')

if not os.path.exists('nvd'):
    os.makedirs('nvd')

if not os.path.exists('nvd/json'):
    os.makedirs('nvd/json')

for filename in re.findall("nvdcve-1.0-[0-9]*\.json\.zip",r.text):
    try:
        print("Getting: "+filename)
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.0/" + filename, stream=True)
    except Exception as e:
        print("An error occurred getting "+filename+": "+e)

    try:
        print(" - storing")
        with open("nvd/json/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)
        # try:
        #     print(" - extracting")
        #     with zipfile.ZipFile("nvd/json/" + filename,"r") as zip_ref:
        #         zip_ref.extractall("nvd/json/")
        #     print(" - removing archive")
        #     os.remove("nvd/json/" + filename)
        # except Exception as e:
        #     print("An error occurred extracting "+filename+": "+e)
        print(" - done!")
    except Exception as e:
        print("An error occurred storing "+filename+": "+e)