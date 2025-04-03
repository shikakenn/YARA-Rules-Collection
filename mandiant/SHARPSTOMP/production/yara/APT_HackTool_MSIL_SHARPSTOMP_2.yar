// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPSTOMP_2
{
    meta:
        id = "3r7azO7tHMtgsOdGz23P2r"
        fingerprint = "v1_sha256_4ed1553f12c607792d7d4e7026ecb36231cd417a06eba8b2925c2c643436b5fe"
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
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 3

    strings:
        $f0 = "mscoree.dll" fullword nocase
        $s0 = { 06 72 [4] 6F [4] 2C ?? 06 72 [4] 6F [4] 2D ?? 72 [4] 28 [4] 28 [4] 2A }
        $s1 = { 02 28 [4] 0A 02 28 [4] 0B 02 28 [4] 0C 72 [4] 28 [4] 72 }
        $s2 = { 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 72 }
        $s3 = "SetCreationTime" fullword
        $s4 = "GetLastAccessTime" fullword
        $s5 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
