// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_TitoSpecial_2
{
    meta:
        id = "2RAlijkwFGzdZe9h8S4gSW"
        fingerprint = "v1_sha256_2f621f8de2a4679e6cbce7f41859eaa3095ca54090c8bfccd3b767590ac91f2c"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the TitoSpecial project. There are 2 GUIDs in this rule as the x86 and x64 versions of this tool use a different ProjectGuid."
        category = "INFO"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 4

    strings:
        $typelibguid1 = "C6D94B4C-B063-4DEB-A83A-397BA08515D3" ascii nocase wide
        $typelibguid2 = "3b5320cf-74c1-494e-b2c8-a94a24380e60" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ($typelibguid1 or $typelibguid2)
}
