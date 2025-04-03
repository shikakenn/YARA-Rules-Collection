// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_REDTEAMMATERIALS_1
{
    meta:
        id = "2YQ5wbqHpENQYAXEtdaF9M"
        fingerprint = "v1_sha256_ca54a1e8335c4256295fc643f5d31eae2e89f020dc7a9b571c4772edaad08022"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'red_team_materials' project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "86c95a99-a2d6-4ebe-ad5f-9885b06eab12" ascii nocase wide
        $typelibguid1 = "e06f1411-c7f8-4538-bbb9-46c928732245" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
