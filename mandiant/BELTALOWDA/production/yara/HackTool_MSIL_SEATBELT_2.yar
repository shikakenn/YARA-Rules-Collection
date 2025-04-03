// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SEATBELT_2
{
    meta:
        id = "4ugBoDlUkJYHx3o0UVizkV"
        fingerprint = "v1_sha256_e48474c5025fd88e3c2824e1e943ff56cde0ea05984aad0249ccf73caa6d4a36"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SeatBelt project."
        category = "INFO"
        md5 = "9f401176a9dd18fa2b5b90b4a2aa1356"
        rev = 3

    strings:
        $typelibguid1 = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
