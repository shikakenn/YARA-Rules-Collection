// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_LUALOADER_2
{
    meta:
        id = "2XMvdFN2bXMYQGF7vIIHRT"
        fingerprint = "v1_sha256_700927768669eda6976071306e991bfaae136279f4265980521597c699fbed88"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"

    strings:
        $ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
        $ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
        $ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
        $ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
        $ss5 = "1F 8B 08 00 00 00 00 00" wide
        $ss6 = "\x00LoadLibrary\x00"
        $ss7 = "\x00GetProcAddress\x00"
        $ss8 = "\x00VirtualProtect\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
