// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_REVOLVER_1
{
    meta:
        id = "76wH7JYWA6LP3RfOpPPsNC"
        fingerprint = "v1_sha256_8df8a56ed55b7857adb95daa643d544a49eb5f1952b4ad3ef757c34dad2ce317"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'revolver' project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide
        $typelibguid1 = "b214d962-7595-440b-abef-f83ecdb999d2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
