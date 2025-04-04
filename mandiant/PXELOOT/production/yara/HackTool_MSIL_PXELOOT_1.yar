// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_PXELOOT_1
{
    meta:
        id = "1vxo7ULmjLrasaXr1KEoCj"
        fingerprint = "v1_sha256_c9892adcb9ff5471235e45988f6662d3b8f984fdafca7024a5781eed50f6c0b3"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the PXE And Loot project."
        category = "INFO"
        md5 = "82e33011ac34adfcced6cddc8ea56a81"
        rev = 7

    strings:
        $typelibguid1 = "78B2197B-2E56-425A-9585-56EDC2C797D6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
