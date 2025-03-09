rule Fake_AdobeReader_EXE
    {
    meta:
        id = "6ZltvvbHRTjXhJDVNZOBx4"
        fingerprint = "v1_sha256_aa090e41620ac1c9c6fba0392ad9a70b20035e7c2e099433d7b63f463b151ff0"
        version = "1.0"
        score = 50
        date = "2014-09-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an fake AdobeReader executable based on filesize OR missing strings in file"
        category = "INFO"

    strings:
        $s1 = "Adobe Systems" ascii
    condition:
        uint16(0) == 0x5a4d and 
        filename matches /AcroRd32.exe/i and 
        not $s1 in (filesize-2500..filesize) 
}

rule Fake_FlashPlayerUpdaterService_EXE
    {
    meta:
        id = "1rFvG51XJaOJ3L7peMhUws"
        fingerprint = "v1_sha256_8d55c46be2eee695cb35f95b45e7448fe1f0ae20c64c201b881bf6fe777d2f2b"
        version = "1.0"
        score = 50
        date = "2014-09-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an fake AdobeReader executable based on filesize OR missing strings in file"
        category = "INFO"

    strings:
        $s1 = "Adobe Systems Incorporated" ascii
    condition:
        uint16(0) == 0x5a4d and 
        filename matches /FlashPlayerUpdateService.exe/i and 
        not $s1 in (filesize-2500..filesize) 
}
