// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_AllTheThings_1
{
    meta:
        id = "3TXttcjUeGCNJFi77NdMts"
        fingerprint = "v1_sha256_e3058095f2a49f8c0f78cb392024795367609b04c1da80210ab8d72c6613ee71"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'AllTheThings' project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "542ccc64-c4c3-4c03-abcd-199a11b26754" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
