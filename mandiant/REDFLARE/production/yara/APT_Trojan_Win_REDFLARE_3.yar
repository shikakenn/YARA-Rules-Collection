// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_3
{
    meta:
        id = "1EAK3ZzNHOLrqax73IrHNQ"
        fingerprint = "v1_sha256_ee104bc145686a134e4d6d620dae7d1dacff7645d47f1a8d7a212327352b8e87"
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
        md5 = "9ccda4d7511009d5572ef2f8597fba4e,ece07daca53dd0a7c23dacabf50f56f1"
        rev = 1

    strings:
        $calc_image_size = { 28 00 00 00 [2-30] 83 E2 1F [4-20] C1 F8 05 [0-8] 0F AF C? [0-30] C1 E0 02 }
        $str1 = "CreateCompatibleBitmap" fullword
        $str2 = "BitBlt" fullword
        $str3 = "runCommand" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
