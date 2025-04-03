// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_PXELOOT_2
{
    meta:
        id = "4z4w7YNqhDECnL5o5dHRIj"
        fingerprint = "v1_sha256_f3770b2b9543e8ed7fdb0d2bc4a71ebe8649157d7130a4369fb5a0c52589acd2"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have the strings of various method names in the PXE And Loot code."
        category = "INFO"
        md5 = "d93100fe60c342e9e3b13150fd91c7d8"
        rev = 5

    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "PXE" ascii nocase wide
        $str2 = "InvestigateRPC" ascii nocase wide
        $str3 = "DhcpRecon" ascii nocase wide
        $str4 = "UnMountWim" ascii nocase wide
        $str5 = "remote WIM image" ascii nocase wide
        $str6 = "DISMWrapper" ascii nocase wide
        $str7 = "findTFTPServer" ascii nocase wide
        $str8 = "DHCPRequestRecon" ascii nocase wide
        $str9 = "DHCPDiscoverRecon" ascii nocase wide
        $str10 = "GoodieFile" ascii nocase wide
        $str11 = "InfoStore" ascii nocase wide
        $str12 = "execute" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
