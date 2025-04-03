// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_MODIFIEDSHARPVIEW_1
{
    meta:
        id = "xbfxuZS5NxL4QnXDBpl6X"
        fingerprint = "v1_sha256_a47c48da998243fab92665649fb9d6ecc6ac32e1fd884c2c0d5ccecb05290c10"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'modifiedsharpview' project."
        category = "INFO"
        md5 = "db0eaad52465d5a2b86fdd6a6aa869a5"
        rev = 3

    strings:
        $typelibguid0 = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
