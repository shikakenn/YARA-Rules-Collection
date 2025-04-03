// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Linux_REDFLARE_1
{
    meta:
        id = "383rivvaj0tmoXdyDvP2fE"
        fingerprint = "v1_sha256_282f11c4c86d88d05f11e92f5483701d9a54c2dd39f21316cd271aa78a338d0f"
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
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        rev = 1

    strings:
        $s1 = "find_applet_by_name" fullword
        $s2 = "bb_basename" fullword
        $s3 = "hk_printf_chk" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}
