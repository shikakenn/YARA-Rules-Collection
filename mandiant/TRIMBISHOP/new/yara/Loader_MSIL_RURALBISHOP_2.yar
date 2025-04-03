// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_RURALBISHOP_2
{
    meta:
        id = "5qLV55me0BEkz8SxFbDMy0"
        fingerprint = "v1_sha256_0467532d643cf0200c6561b0724c884230892bf59db163c311b7d4f8acbb63d6"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1

    strings:
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
        $ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
        $tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
