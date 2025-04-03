// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharpStomp_1
{
    meta:
        id = "TqxxVNDzeTnnSYXesILv9"
        fingerprint = "v1_sha256_fd0a3d046734d48be74d9a74f27570468550d21911c54ca82c81a1d64e9fdd17"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharpStomp project."
        category = "INFO"
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 4

    strings:
        $typelibguid1 = "41f35e79-2034-496a-8c82-86443164ada2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
