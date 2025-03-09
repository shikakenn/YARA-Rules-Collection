// yara sigs for detecting common suicide scripts

rule SuicideScriptL1
{
    meta:
        id = "OMOoMYg2pTThFFr9O8muy"
        fingerprint = "v1_sha256_cde484fc38ab5c85ae82d3a5cc6cf3e6832c7e0976770d7eb1c4a2a7cf383e42"
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
        $ = ":L1\ndel \"%s\"\nif exist \"%s\" goto L1\ndel \"%s\"\n"
    condition:
        any of them
}

rule SuicideScriptR1_Multi
{
    meta:
        id = "5mE0owJ3xCzOZ1EiI0N7R5"
        fingerprint = "v1_sha256_a0fa854e81119d6a5e35417718166763f73cb5878e42b63c93aa396c16c17a42"
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
        $ = "\" goto R1\ndel /a \""
        $ = "\"\nif exist \""
        $ = "@echo off\n:R1\ndel /a \""
    condition:
        all of them
}

rule SuicideScriptR
{
    // joanap, joanapCleaner
    meta:
        id = "gsxLw2ytbb2Ooc2H84Ovr"
        fingerprint = "v1_sha256_4a18ab785e26e4e0ec997f26cc3d40861fc6c6b9338b51a374591e3933d9c385"
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
        $ = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
        
    condition:
        all of them

}
