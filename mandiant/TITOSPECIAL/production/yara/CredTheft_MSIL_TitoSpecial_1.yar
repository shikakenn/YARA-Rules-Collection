// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_TitoSpecial_1
{
    meta:
        id = "6BHxrY4DT7DmSmz7uiWaB1"
        fingerprint = "v1_sha256_4ac9a5ede4aea5d73545b459eb635f87ce08ba521afa48b76d2cfa94f1379226"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have the strings of various method names in the TitoSpecial code."
        category = "INFO"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 4

    strings:
        $str1 = "Minidump" ascii wide
        $str2 = "dumpType" ascii wide
        $str3 = "WriteProcessMemory" ascii wide
        $str4 = "bInheritHandle" ascii wide
        $str5 = "GetProcessById" ascii wide
        $str6 = "SafeHandle" ascii wide
        $str7 = "BeginInvoke" ascii wide
        $str8 = "EndInvoke" ascii wide
        $str9 = "ConsoleApplication1" ascii wide
        $str10 = "getOSInfo" ascii wide
        $str11 = "OpenProcess" ascii wide
        $str12 = "LoadLibrary" ascii wide
        $str13 = "GetProcAddress" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($str*)
}
