// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_8
{
    meta:
        id = "1ytAaDBkdeNlJUUs3bl29p"
        fingerprint = "v1_sha256_5b8a0402886daebefb995e7df0877d51727c5b8dc58eeb8ff16ceec5e7811a20"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
        rev = 1

    strings:
        $1 = "PSRunner.PSRunner" fullword
        $2 = "CorBindToRuntime" fullword
        $3 = "ReportEventW" fullword
        $4 = "InvokePS" fullword wide
        $5 = "runCommand" fullword
        $6 = "initialize" fullword
        $trap = { 03 40 00 80 E8 [4] CC }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
