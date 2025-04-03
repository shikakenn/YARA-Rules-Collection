// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SEATBELT_1
{
    meta:
        id = "71KkOkTn8rnvTVgv9XNTY8"
        fingerprint = "v1_sha256_4248e5561ef60e725c23efc89c899d6fc8be5bf2142f700fb70daecd72c30dd8"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have regex and format strings found in the public tool SeatBelt. Due to the nature of the regex and format strings used for detection, this rule should detect custom variants of the SeatBelt project."
        category = "INFO"
        md5 = "848837b83865f3854801be1f25cb9f4d"
        rev = 3

    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "{ Process = {0}, Path = {1}, CommandLine = {2} }" ascii nocase wide
        $str2 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii nocase wide
        $str3 = "LogonId=\"(\\d+)\"" ascii nocase wide
        $str4 = "{0}.{1}.{2}.{3}" ascii nocase wide
        $str5 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii nocase wide
        $str6 = "*[System/EventID={0}]" ascii nocase wide
        $str7 = "*[System[TimeCreated[@SystemTime >= '{" ascii nocase wide
        $str8 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii nocase wide
        $str9 = "{0}" ascii nocase wide
        $str10 = "{0,-23}" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
