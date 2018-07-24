import sqlite3

class DBManager:

    def __init__(self, load):
        self.connect('cvedatabase.db')
        if not load:
            self.createTables('createNVDTables.sql')
        else:
            print("Loaded tables successfully")

#--------------------------------------------------------------------------------------------------

    def connect(self, db):
        self.conn = sqlite3.connect(db)
        print("Opened database successfully")

#--------------------------------------------------------------------------------------------------

    def createTables(self, init):
        with open(init, 'r') as f:
            sql = f.read()
            self.conn.executescript(sql)
        print("Created tables successfully")

#--------------------------------------------------------------------------------------------------

    def commit(self):
        self.conn.commit()
#--------------------------------------------------------------------------------------------------

    def close(self):
        print("Database closed successfully")
        self.conn.close()

#--------------------------------------------------------------------------------------------------

    def addCVEitem(self, i, c, m):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        i: CVE code ("cve" TEXT)
        c: Date of Creation ("publishedDate" TEXT)
        m: Date of Last Modification ("lastModifiedDate" TEXT)
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO cve_items VALUES (NULL, ?, ?, ?);", (i,c,m))
        #self.conn.commit()
        #print("CVE entry inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addCVEdescription(self, i, l, d):
        """
        Adds CVE description to cve_descriptions table in database.

        Arguments:
        i: ID in cve_items ("cveId" TEXT)
        l: Description Language ("language" TEXT)
        d: Description of CVE ("description" TEXT)
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO cve_descriptions VALUES (NULL, ?, ?, ?);", (i,l,d))
        #self.conn.commit()
        #print("CVE description inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addCVEissue(self, c, p):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        c: CVE Id ("cveId" INTEGER)
        p: Product Version Id ("productVersionId" INTEGER)
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO cve_issue VALUES (NULL, ?, ?);", (c,p))
        #self.conn.commit()
        #print("CVE entry inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addProductVersion(self, p, v):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        p: Product Id ("productId" INTEGER)
        v: Version ("version" TEXT)
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO product_version VALUES (NULL, ?, ?);", (p,v))
        #self.conn.commit()
        #print("CVE entry inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addProductInfo(self, v, p):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        v: Vendor Id ("vendorId" INTEGER)
        p: Product Name ("productName" TEXT)
        """
        cur = self.conn.cursor()
        # print("Product: "+p)
        # p = p.replace("\'", "\'\")
        # print("Product: "+p)
        cur.execute("SELECT id FROM product_info WHERE productName = '"+p.replace("\'", "\'\'")+"'")
        all_rows = cur.fetchall()
        if (len(all_rows) != 0):
            return all_rows[0][0]
        else:
            cur.execute("INSERT INTO product_info VALUES (NULL, ?, ?);", (v,p))

        #self.conn.commit()
        #print("CVE entry inserted successfully")
            return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addVendorInfo(self, v):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        v: Vendor Name ("vendorName" TEXT)
        """
        #print("Vendor: "+v)
        #v = v.replace("\'", "")
        cur = self.conn.cursor()
        #print("Vendor: "+v)
        cur.execute("SELECT id FROM vendor_info WHERE vendorName = '"+v.replace("\'", "\'\'")+"'")
        all_rows = cur.fetchall()
        if (len(all_rows) != 0):
            return all_rows[0][0]
        else:
            cur.execute("INSERT INTO vendor_info VALUES (NULL, ?);", ((v,)))
        #self.conn.commit()
        #print("CVE entry inserted successfully")
            return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addNVD(self, i, v2, v3):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        i: CVE code ("cveId" INTEGER)
        c: Base Metric V2 id ("baseMetricV2id" INTEGER)
        m: Base Metric V3 id ("baseMetricV3id" INTEGER)
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO nvd_impact VALUES (NULL, ?, ?, ?);", (i,v2,v3))
        #self.conn.commit()
        #print("NVD entry inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addNVD_BMV2(self, cvssv2, es, ims, oap, oop, oup, s, uir):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        cvssv2: cvssv2 Id ("cvssV2" INTEGER)
        es:     Exploitability Score ("exploitabilityScore" TEXT)
        ims:    Impact Score ("impactScore" TEXT)
        oap:    Obtain All Privilege ("obtainAllPrivilege" TEXT)
        oop:    Obtain Other Privilege ("obtainOtherPrivilege" TEXT)
        oup:    Obtain User Privilege ("obtainUserPrivilege" TEXT)
        s:      Severity ("severity" TEXT)
        uir:    User Interaction Required ("userInteractionRequired" TEXT)
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO nvd_baseMetricV2 VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?);", (cvssv2, es, ims, oap, oop, oup, s, uir))
        #self.conn.commit()
        #print("NVD base Metric V2 inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addNVD_BMV3(self, cvssv3, es, ims):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        cvssv3: cvssv3 Id ("cvssV3" INTEGER)
        es:     Exploitability Score ("exploitabilityScore" TEXT)
        ims:    Impact Score ("impactScore" TEXT)
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO nvd_baseMetricV3 VALUES (NULL, ?, ?, ?, ?);", (cvssv3, es, ims))
        #self.conn.commit()
        #print("NVD base Metric V3 inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addNVD_CVSS_V2(self, ac, av, a, ai, bs, ci, ii, vs):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        ac: access Complexity ("accessComplexity" TEXT)
        av: access Vector ("accessVector" TEXT)
        a:  authentication ("authentication" TEXT)
        ai: availability Impact ("availabilityImpact" TEXT)
        bs: base Score ("baseScore" TEXT)
        ci: confidentiality Impact ("confidentialityImpact" TEXT)
        ii: integrity Impact ("integrityImpact" TEXT)
        vs: vector String "vectorString" TEXT)
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO nvd_cvssV2 VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?);", (ac, av, a, ai, bs, ci, ii, vs))
        #self.conn.commit()base Metric V2
        #print("NVD CVSS V2 inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def addNVD_CVSS_V3(self, ac, av, ai, bs, sev, ci, ii, rp, s, ui, vs):
        """
        Adds CVE entry to cve_items table in database.

        Arguments:
        i:  "id" INTEGER PRIMARY KEY,
        ac: "attackComplexity" TEXT,
        av: "attackVector" TEXT,
        ai: "availabilityImpact" TEXT,
        bs: "baseScore" TEXT,
        sev:"baseSeverity" TEXT,
        ci: "confidentialityImpact" TEXT,
        ii: "integrityImpact" TEXT,
        rp: "privilegesRequired" TEXT,
        s:  "scope" TEXT,
        ui: "userInteraction" TEXT,
        vs: "vectorString" TEXT
        """
        cur = self.conn.cursor()
        cur.execute("INSERT INTO nvd_cvssV3 VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", (ac, av, ai, bs, sev, ci, ii, rp, s, ui, vs))
        #self.conn.commit()
        #print("NVD CVSS V3 inserted successfully")
        return cur.lastrowid

#--------------------------------------------------------------------------------------------------

    def getByYear(self, y):
        """
        Return CVEs for given year

        Arguments:
        y: Year of CVEs to return

        """
        py = str(y)+"-00-00T00:00Z"
        ny = str(y+1)+"-00-00T00:00Z"
        cur = self.conn.cursor()
        cur.execute("SELECT * \
                    FROM cve_items \
                    WHERE publishedDate > ? AND publishedDate < ?",
                    (py, ny))
        all_rows = cur.fetchall()

        return [(row[0], row[1], row[2], row[3]) for row in all_rows]

#--------------------------------------------------------------------------------------------------

    def findByDescription(self, s):
        """
        Return CVEs for given year

        Arguments:
        s: String to look for

        """
        cur = self.conn.cursor()
        cur.execute("SELECT \
                        cve_items.cve, \
                        cve_descriptions.description \
                    FROM cve_items \
                    JOIN cve_descriptions \
                        ON cve_items.id = cve_descriptions.cveId \
                    WHERE cve_descriptions.description LIKE '%"+s+"%' --case-insensitive")
        all_rows = cur.fetchall()

        return [(row[0], row[1]) for row in all_rows]

#--------------------------------------------------------------------------------------------------

    def getFullInfo(self, cve):
        """
        Return CVEs for given year

        Arguments:
        cve: CVE

        """
        cur = self.conn.cursor()
        cur.execute("SELECT \
                        cve_items.cve, \
                        cve_descriptions.description \
                    FROM \
                        cve_items \
                        JOIN cve_descriptions \
                            ON cve_items.id = cve_descriptions.cveId \
                    WHERE \
                         cve_items.cve = ?",
                    (cve,))

        row = cur.fetchone()

        return (row[0], row[1])

#--------------------------------------------------------------------------------------------------

    def getImpact(self, cve):
        """
        Return CVEs for given year

        Arguments:
        s: String to look for

        """
        cur = self.conn.cursor()
        cur.execute("SELECT \
                        cve_items.cve, \
                        nvd_baseMetricv2.cvssV2,\
                        nvd_baseMetricv3.cvssV3\
                    FROM cve_items \
                    JOIN nvd_impact \
                        ON cve_items.id = nvd_impact.cveId\
                    LEFT JOIN nvd_baseMetricv2\
                        ON nvd_impact.baseMetricV2id = nvd_baseMetricv2.id\
                    LEFT JOIN nvd_baseMetricv3\
                        ON nvd_impact.baseMetricV3id = nvd_baseMetricv3.id\
                    WHERE cve_items.cve = ?", \
                    (cve,))
        all_rows = cur.fetchall()

        return [(row[0], row[1], row[2]) for row in all_rows]

#--------------------------------------------------------------------------------------------------

    def getProductsByDescription(self, d):
        """
        Return CVEs for given year

        Arguments:
        s: String to look for

        """
        cur = self.conn.cursor()
        cur.execute("SELECT\
                        cve_items.cve,\
                        vendor_info.vendorName,\
                        product_info.productName,\
                        product_version.version,\
                        cve_descriptions.description\
                    FROM\
                        cve_items\
                    JOIN cve_issue\
                        ON cve_issue.cveId = cve_items.id\
                    JOIN cve_descriptions\
                            ON cve_items.id = cve_descriptions.cveId\
                    JOIN product_version\
                        ON product_version.id = cve_issue.productVersionId\
                    JOIN product_info\
                        ON product_info.id = product_version.productId\
                    JOIN vendor_info\
                        ON vendor_info.id = product_info.vendorId\
                    WHERE\
	                    cve_descriptions.description LIKE '%"+d+"%'")
        all_rows = cur.fetchall()

        return [(row[0], row[1], row[2], row[3], row[4]) for row in all_rows]