// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPSTOMP_1
{
    meta:
        id = "5CNbZIGnTuMjy7jfjN89Vm"
        fingerprint = "v1_sha256_af8aa0e87d8b6623a908fde5014f3849cd0ca20d5926c798be82ce4eab2668bb"
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
        $s0 = "mscoree.dll" fullword nocase
        $s1 = "timestompfile" fullword nocase
        $s2 = "sharpstomp" fullword nocase
        $s3 = "GetLastWriteTime" fullword
        $s4 = "SetLastWriteTime" fullword
        $s5 = "GetCreationTime" fullword
        $s6 = "SetCreationTime" fullword
        $s7 = "GetLastAccessTime" fullword
        $s8 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
