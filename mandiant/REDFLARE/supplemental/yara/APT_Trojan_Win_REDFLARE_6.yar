// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_6
{
    meta:
        id = "67XYZWt1uIyeydBUAI6ucT"
        fingerprint = "v1_sha256_1e6f8320e0c0b601fc72fa4d9c61e46adfbcd84638c97da5988ca848e036312a"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "294b1e229c3b1efce29b162e7b3be0ab, 6902862bd81da402e7ac70856afbe6a2"
        rev = 2

    strings:
        $s1 = "RevertToSelf" fullword
        $s2 = "Unsuccessful" fullword
        $s3 = "Successful" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
