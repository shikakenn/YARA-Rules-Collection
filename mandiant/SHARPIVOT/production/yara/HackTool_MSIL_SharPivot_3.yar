// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPivot_3
{
    meta:
        id = "5eC9yeWGuUd7Pkvio1hfiK"
        fingerprint = "v1_sha256_ecf13e47e409efd68b508735a84be6a1627f5b0c0cea6b90434fc9ba5b1d8cf5"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have the strings of various method names in the SharPivot code."
        category = "INFO"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3

    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "SharPivot" ascii wide
        $str2 = "ParseArgs" ascii wide
        $str3 = "GenRandomString" ascii wide
        $str4 = "ScheduledTaskExists" ascii wide
        $str5 = "ServiceExists" ascii wide
        $str6 = "lpPassword" ascii wide
        $str7 = "execute" ascii wide
        $str8 = "WinRM" ascii wide
        $str9 = "SchtaskMod" ascii wide
        $str10 = "PoisonHandler" ascii wide
        $str11 = "SCShell" ascii wide
        $str12 = "SchtaskMod" ascii wide
        $str13 = "ServiceHijack" ascii wide
        $str14 = "commandArg" ascii wide
        $str15 = "payloadPath" ascii wide
        $str16 = "Schtask" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
