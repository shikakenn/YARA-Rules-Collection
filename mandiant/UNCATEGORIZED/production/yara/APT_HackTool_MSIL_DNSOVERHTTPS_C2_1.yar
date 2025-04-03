// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_DNSOVERHTTPS_C2_1
{
    meta:
        id = "4BiGkqHQspaXxJum90UagA"
        fingerprint = "v1_sha256_a482161bbd8e249977f28466ff1381d4693495f8b8ccd9183ae4fde1ec1471eb"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'DoHC2' External C2 project."
        category = "INFO"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
        $typelibguid1 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
