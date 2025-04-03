// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_Rubeus_1
{
    meta:
        id = "7EAZcToGRydrZpgbntvimB"
        fingerprint = "v1_sha256_ad954f9922ab564d68cb4515b080f6ee69476a8d87f0038e2ae4c222f0e182d7"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public Rubeus project."
        category = "INFO"
        md5 = "66e0681a500c726ed52e5ea9423d2654"
        rev = 4

    strings:
        $typelibguid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}
