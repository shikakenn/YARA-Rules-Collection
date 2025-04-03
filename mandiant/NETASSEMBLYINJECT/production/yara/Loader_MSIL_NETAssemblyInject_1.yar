// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Loader_MSIL_NETAssemblyInject_1
{
    meta:
        id = "5vvXww2URpLEgl4xlR9Gtj"
        fingerprint = "v1_sha256_9a43df9ee26a44f4db5c2d22fbc1a6c86c5af0c9d44a79c6627a4cc8cf31bb8d"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NET-Assembly-Inject' project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "af09c8c3-b271-4c6c-8f48-d5f0e1d1cac6" ascii nocase wide
        $typelibguid1 = "c5e56650-dfb0-4cd9-8d06-51defdad5da1" ascii nocase wide
        $typelibguid2 = "e8fa7329-8074-4675-9588-d73f88a8b5b6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
