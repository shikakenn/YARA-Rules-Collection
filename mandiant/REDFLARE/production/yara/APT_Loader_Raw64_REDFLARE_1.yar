// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Raw64_REDFLARE_1
{
    meta:
        id = "6Y4k3Vd6jM1TFbx87jr7YL"
        fingerprint = "v1_sha256_dac122ccece8a6dd35a5fe9d37860a612aa50ab469b79f4375dbe776f60c7b57"
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
        md5 = "5e14f77f85fd9a5be46e7f04b8a144f5"
        rev = 1

    strings:
        $load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}
