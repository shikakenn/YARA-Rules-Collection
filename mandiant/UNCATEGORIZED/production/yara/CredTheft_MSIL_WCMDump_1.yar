// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_WCMDump_1
{
    meta:
        id = "6Di3gAeWHSXZhDuYLtdm37"
        fingerprint = "v1_sha256_9fbf53e551342695b306b10f30a3fe32dff359bd70e84e1fa1f190772f5dcbe3"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WCMDump' project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "21e322f2-4586-4aeb-b1ed-d240e2a79e19" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
