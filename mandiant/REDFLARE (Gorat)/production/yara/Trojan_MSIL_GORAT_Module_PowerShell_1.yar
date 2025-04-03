// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Trojan_MSIL_GORAT_Module_PowerShell_1
{
    meta:
        id = "3DBBEyl3aPrOgX2dO9DUDj"
        fingerprint = "v1_sha256_e596bc0316a4ef85f04c2683ebc7c94bf9b831843232c33e62c84991e4caeb97"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Module - PowerShell' project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "38d89034-2dd9-4367-8a6e-5409827a243a" ascii nocase wide
        $typelibguid1 = "845ee9dc-97c9-4c48-834e-dc31ee007c25" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
