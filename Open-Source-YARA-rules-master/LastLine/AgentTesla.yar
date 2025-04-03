rule Agent_Tesla : Agent_Tesla
{
    meta:
        id = "2KlECZXAO0yOVYSMna6DiP"
        fingerprint = "v1_sha256_beb4bebad025c56c782c5ff5938906e9da73416aed20b919a72cd8d790a1c8d5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "LastLine"
        description = "NA"
        category = "INFO"
        reference = "https://www.lastline.com/labsblog/surge-of-agent-tesla-threat-report/"

     strings:
          $pass = "amp4Z0wpKzJ5Cg0GDT5sJD0sMw0IDAsaGQ1Afik6NwXr6rrSEQE=" fullword ascii wide nocase
          $salt = "aGQ1Afik6NampDT5sJEQE4Z0wpsMw0IDAD06rrSswXrKzJ5Cg0G=" fullword ascii wide nocase
 
     condition:
           uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and all of them
}
