CREATE TABLE IF NOT EXISTS cve_items (
    "id" INTEGER PRIMARY KEY,
    "cve" TEXT,
    "publishedDate" TEXT,
    "lastModifiedDate" TEXT
);

CREATE TABLE IF NOT EXISTS cve_descriptions (
    "id" INTEGER PRIMARY KEY,
    "cveId" INTEGER,
    "language" TEXT,
    "description" TEXT
);

CREATE TABLE IF NOT EXISTS cve_issue (
    "id" INTEGER PRIMARY KEY,
    "cveId" INTEGER,
    "productVersionId" INTEGER
);

CREATE TABLE IF NOT EXISTS vendor_info (
    "id" INTEGER PRIMARY KEY,
    "vendorName" TEXT
);

CREATE TABLE IF NOT EXISTS product_info (
    "id" INTEGER PRIMARY KEY,
    "vendorId" INTEGER,
    "productName" TEXT
);

CREATE TABLE IF NOT EXISTS product_version (
    "id" INTEGER PRIMARY KEY,
    "productId" INTEGER,
    "version" TEXT
);

CREATE TABLE IF NOT EXISTS nvd_impact (
    "id" INTEGER PRIMARY KEY,
    "cveId" INTEGER,
    "baseMetricV2id" INTEGER,
    "baseMetricV3id" INTEGER
);

CREATE TABLE IF NOT EXISTS nvd_baseMetricV2 (
    "id" INTEGER PRIMARY KEY,
    "cvssV2" INTEGER,
    "exploitabilityScore" TEXT,
    "impactScore" TEXT,
    "obtainAllPrivilege" TEXT,
    "obtainOtherPrivilege" TEXT,
    "obtainUserPrivilege" TEXT,
    "severity" TEXT,
    "userInteractionRequired" TEXT
);

CREATE TABLE IF NOT EXISTS nvd_baseMetricV3 (
    "id" INTEGER PRIMARY KEY,
    "cvssV3" INTEGER,
    "exploitabilityScore" TEXT,
    "impactScore" TEXT
);

CREATE TABLE IF NOT EXISTS nvd_cvssV2 (
    "id" INTEGER PRIMARY KEY,
    "accessComplexity" TEXT,
    "accessVector" TEXT,
    "authentication" TEXT,
    "availabilityImpact" TEXT,
    "baseScore" TEXT,
    "confidentialityImpact" TEXT,
    "integrityImpact" TEXT,
    "vectorString" TEXT
);

CREATE TABLE IF NOT EXISTS nvd_cvssV3 (
    "id" INTEGER PRIMARY KEY,
    "attackComplexity" TEXT,
    "attackVector" TEXT,
    "availabilityImpact" TEXT,
    "baseScore" TEXT,
    "baseSeverity" TEXT,
    "confidentialityImpact" TEXT,
    "integrityImpact" TEXT,
    "privilegesRequired" TEXT,
    "scope" TEXT,
    "userInteraction" TEXT,
    "vectorString" TEXT
);

CREATE INDEX vendor0 ON vendor_info (vendorName);

CREATE INDEX product0 ON product_info (productName);