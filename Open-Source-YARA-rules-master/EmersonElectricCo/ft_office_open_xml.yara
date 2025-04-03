// References:
// http://www.garykessler.net/library/file_sigs.html
// https://issues.apache.org/jira/browse/TIKA-257

rule ft_office_open_xml
{
    meta:
        id = "7dmcZdVmZZToSHmRAkMWyp"
        fingerprint = "v1_sha256_7bb015e106082d3242246ec58d7fdb8189a75942cfe292ed8c3265343088f505"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "NA"
        category = "INFO"
        company = "Emerson"
        lastmod = "20140915"
        desc = "Simple metadata attribute indicative of Office Open XML format. Commonly seen in modern office files."

   strings:
      $OOXML = "[Content_Types].xml"

   condition:
      $OOXML at 30
}

