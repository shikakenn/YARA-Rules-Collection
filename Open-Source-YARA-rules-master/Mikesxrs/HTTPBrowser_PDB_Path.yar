rule HTTPBrowser
{
    meta:
        id = "3dZ6nd73WKcpM9ES4idCRE"
        fingerprint = "v1_sha256_1e13e861ced9704afd90d8259b0d53a7a2d6f79e33659acaee635160cc56b135"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mikesxrs"
        description = "PDB Path in httpbrowser malware"
        category = "INFO"
        reference = "hhttps://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage"

  strings:
    $pdb1 = "J:\\TokenControlV3\\ServerDll\\Release\\ServerDll.pdb"
    
  condition:
    any of them
}
