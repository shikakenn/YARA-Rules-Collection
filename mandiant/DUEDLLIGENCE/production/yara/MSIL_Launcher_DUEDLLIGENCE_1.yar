// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule MSIL_Launcher_DUEDLLIGENCE_1
{
    meta:
        id = "2Tzv4RA6uD0wJJWcMxEOgd"
        fingerprint = "v1_sha256_bd6abaa909f0c776d81ed1115e875888336661c91df3881f4f3ea5dd27e115f8"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'DUEDLLIGENCE' project."
        category = "INFO"
        md5 = "a91bf61cc18705be2288a0f6f125068f"
        rev = 1

    strings:
        $typelibguid0 = "73948912-cebd-48ed-85e2-85fcd1d4f560" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
