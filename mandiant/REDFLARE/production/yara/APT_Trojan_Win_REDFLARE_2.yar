// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_2
{
    meta:
        id = "5UwP6DJcKcHVamHMjImcpt"
        fingerprint = "v1_sha256_1f2e1f644b1932486444dfda30b7dad7f50121f59fa493eb8a1a0528ae46db26"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1,05b99d438dac63a5a993cea37c036673"
        rev = 2

    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "Cookie: SID1=%s" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
