// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPNATIVEZIPPER_1
{
    meta:
        id = "6ubBcVZXBsMG3pWR7w44sm"
        fingerprint = "v1_sha256_fa54375b21abbb613e695f70a15233575fbe6e0536716544bb3b527f5e3ed8c6"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnativezipper' project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "de5536db-9a35-4e06-bc75-128713ea6d27" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
