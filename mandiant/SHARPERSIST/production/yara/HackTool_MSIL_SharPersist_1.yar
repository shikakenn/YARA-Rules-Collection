// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPersist_1
{
    meta:
        id = "3X6iiRIRJy5G19NxZLlSV3"
        fingerprint = "v1_sha256_cf480026c31b522850e25ba2d7986773d9c664242a2667ecd33151621c98c91e"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPersist project."
        category = "INFO"
        md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
        rev = 1

    strings:
        $typelibguid1 = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
