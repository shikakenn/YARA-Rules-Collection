// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_Raw_Generic_4
{
    meta:
        id = "52Ed5dzGILdKa7tM4l85pK"
        fingerprint = "v1_sha256_8ffd23631c1a9d1abe6695858ec34d61261b3b3f097be94372f3f34e46e7211e"
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
        md5 = "f41074be5b423afb02a74bc74222e35d"
        rev = 1

    strings:
        $s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
        $s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }
    condition:
        uint16(0) != 0x5A4D and all of them
}
