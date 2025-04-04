// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_RuralBishop_3
{
    meta:
        id = "7R5l5XxEYi8QqgyD1Bq2FN"
        fingerprint = "v1_sha256_a4c55dede432c249e36e96ca09555448b0343969d389bfdb4bd459fe34e05ea1"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public RuralBishop project."
        category = "INFO"
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        rev = 3

    strings:
        $typelibguid1 = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
