// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharpHound_3
{
    meta:
        id = "71wGixLDfFwNvqlXYZy9x2"
        fingerprint = "v1_sha256_baeea6cae42c755ee389378229b2b206c82f60f75a5ce5f9cfa06871fc9507d1"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SharpHound3 project."
        category = "INFO"
        md5 = "eeedc09570324767a3de8205f66a5295"
        rev = 4

    strings:
        $typelibguid1 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
