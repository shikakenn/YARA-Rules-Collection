// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_SHARPDACL_1
{
    meta:
        id = "6DgKUsoUuAohIQroAXMxmN"
        fingerprint = "v1_sha256_5f44ec5ddded18fb3a9132b469b2fe7ccbffb3f907325485f0f72fe3d6bbfa23"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdacl' project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "b3c17fb5-5d5a-4b14-af3c-87a9aa941457" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
