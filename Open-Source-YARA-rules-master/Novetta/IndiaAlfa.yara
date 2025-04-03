rule IndiaAlfa_One
{
    meta:
        id = "6Zsw40MFX9bnNyqFDHRTeB"
        fingerprint = "v1_sha256_8d349e74605ea58d26893d44a650d10ff7b13fc75b1ef4224abe305bc03870a9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $ = "HwpFilePathCheck.dll"
        $ = "AdobeArm.exe"
        $ = "OpenDocument"
        
    condition:
        2 of them

}

rule IndiaAlfa_Two
{
    meta:
        id = "2kiF8g5zMC3otAi23F57Rn"
        fingerprint = "v1_sha256_01eae7fe0901899963539685dc94202f7c5a0d7b42a6899210c255e2cddc1785"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $ = "ExePath: %s\nXlsPath: %s\nTmpPath: %s\n"
        
    condition:
        any of them

}
