# NVD - National Vulnerability Dictionary to Database
#
# Sometimes a dictionary is just not enough
# This builds a basic database from the dictionary (NVD)

from os import listdir
from os.path import isfile, join
import zipfile
import json
import pickle
import time
from dbmanagerNVD import DBManager

start = time.time()

NVD_base = {}

db = DBManager(False)

with open("nvd/" + "NVD_JSON_store.pkl", 'rb') as f:
    NVD_base = pickle.load(f)

print(NVD_base.keys())
print("")

for key, value in NVD_base.items():
    print(key +": " + str(len(value["CVE_Items"])) + " CVEs")
    print("")
    for entry in NVD_base[key]["CVE_Items"]:

        CVEid = entry["cve"]["CVE_data_meta"]["ID"]
        CVEpdate = entry["publishedDate"]
        CVEmdate = entry["lastModifiedDate"]
        pos = db.addCVEitem(CVEid, CVEpdate, CVEmdate)

        print("Added " + CVEid)

        for vendor in entry["cve"]["affects"]["vendor"]["vendor_data"]:
            vendorID = db.addVendorInfo(vendor["vendor_name"])
            for product in vendor["product"]["product_data"]:
                productID = db.addProductInfo(vendorID,product["product_name"])
                for version in product["version"]["version_data"]:
                    versionID = db.addProductVersion(productID, version["version_value"])
                    db.addCVEissue(pos,versionID)

        for decription in entry["cve"]["description"]["description_data"]:
            desLang = decription["lang"]
            desDescription = decription["value"]
            db.addCVEdescription(pos, desLang, desDescription)



        bmv2id = None
        bmv3id = None

        try:
            bm2 = entry["impact"]["baseMetricV2"]
            c2ac = bm2["cvssV2"]["accessComplexity"]
            c2av = bm2["cvssV2"]["accessVector"]
            c2a = bm2["cvssV2"]["authentication"]
            c2ai = bm2["cvssV2"]["availabilityImpact"]
            c2bs = bm2["cvssV2"]["baseScore"]
            c2ci = bm2["cvssV2"]["confidentialityImpact"]
            c2ii = bm2["cvssV2"]["integrityImpact"]
            c2vs = bm2["cvssV2"]["vectorString"]
            cvss2id = db.addNVD_CVSS_V2(c2ac, c2av, c2a, c2ai, c2bs, c2ci, c2ii, c2vs)

            bm2es = bm2["exploitabilityScore"]
            bm2ims = bm2["impactScore"]
            bm2oap = bm2["obtainAllPrivilege"]
            bm2oop = bm2["obtainOtherPrivilege"]
            bm2oup = bm2["obtainUserPrivilege"]
            bm2s = bm2["severity"]
            bm2uir = bm2["userInteractionRequired"]
            bmv2id = db.addNVD_BMV2(cvss2id, bm2es, bm2ims, bm2oap, bm2oop, bm2oup, bm2s, bm2uir)

        except:
            #print("No base Metric V2 info")
            pass

        try:
            bm3 = entry["impact"]["baseMetricV3"]
            c3ac = bm3["cvssV3"]["attackComplexity"]
            c3av = bm3["cvssV3"]["attackVector"]
            c3ai = bm3["cvssV3"]["availabilityImpact"]
            c3bs = bm3["cvssV3"]["baseScore"]
            c3sev = bm3["cvssV3"]["baseSeverity"]
            c3ci = bm3["cvssV3"]["confidentialityImpact"]
            c3ii = bm3["cvssV3"]["integrityImpact"]
            c3rp = bm3["cvssV3"]["privilegesRequired"]
            c3s = bm3["cvssV3"]["scope"]
            c3ui = bm3["cvssV3"]["userInteraction"]
            c3vs = bm3["cvssV3"]["vectorString"]
            cvss3id = db.addNVD_CVSS_V3(c3ac, c3av, c3ai, c3bs, c3sev, c3ci, c3ii, c3rp, c3s, c3ui, c3vs)

            bm3es = bm3["exploitabilityScore"]
            bm3ims = bm3["impactScore"]
            bmv3id = db.addNVD_BMV3(cvss3id, bm3es, bm3ims)

        except:
            #print("No base Metric V3 info")
            pass

        nvdpos = db.addNVD(pos, bmv2id, bmv3id)

    print("-------------------")

db.commit()

db.close()