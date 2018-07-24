import requests
import re
import os

r = requests.get('https://nvd.nist.gov/vuln/data-feeds#XML_FEED')

if not os.path.exists('nvd'):
    os.makedirs('nvd')

if not os.path.exists('nvd/xml'):
    os.makedirs('nvd/xml')

for filename in re.findall("nvdcve-2.0-[0-9]*\.xml\.zip",r.text):
    try:
        print("Getting: "+filename)
        r_file = requests.get("https://nvd.nist.gov/feeds/xml/cve/2.0/" + filename, stream=True)
    except Exception as e:
        print("An error occurred getting "+filename+": "+e)

    try:
        print(" - storing")
        with open("nvd/xml/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)
        print(" - done!")
    except Exception as e:
        print("An error occurred storing "+filename+": "+e)