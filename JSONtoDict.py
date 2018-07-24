# NVD - National Vulnerability Dictionary
#
# Simple script that stuffs the JSON files into a dictionary.
# This is for that that don't like databases, or just feel like scripting stuff :)

from os import listdir
from os.path import isfile, join
import zipfile
import json
import pickle

NVD_base = {}

files = [f for f in listdir("nvd/json/") if isfile(join("nvd/json/", f))]
files.sort()

for file in files:
    archive = zipfile.ZipFile(join("nvd/json/", file), 'r')
    jsonfile = archive.open(archive.namelist()[0])

    cve_dict = json.loads(jsonfile.read().decode('utf-8'))

    year = file.split("-")[2].split(".")[0]

    NVD_base[year] = cve_dict

    print("merged " + str(year))

    jsonfile.close()

print("Storing NVDstore.pkl")

with open("nvd/" + "NVD_JSON_store.pkl", 'wb') as f:
    pickle.dump(NVD_base,f)