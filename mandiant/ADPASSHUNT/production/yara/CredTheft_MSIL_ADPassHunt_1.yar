// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule CredTheft_MSIL_ADPassHunt_1
{
    meta:
        id = "3imHzSHy0mr8NqTFF5H82e"
        fingerprint = "v1_sha256_85c7c147d6bf5b7cb417ff2910a3e7ab3be5e8a3651758c07f8f0ed42b5964d8"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public ADPassHunt project."
        category = "INFO"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 4

    strings:
        $typelibguid = "15745B9E-A059-4AF1-A0D8-863E349CD85D" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}
