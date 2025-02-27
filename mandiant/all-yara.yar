// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"

rule HackTool_MSIL_Rubeus_1
{
    meta:
        id = "6Ir9vwObaWwVq8OJIM7Lfa"
        fingerprint = "v1_sha256_ad954f9922ab564d68cb4515b080f6ee69476a8d87f0038e2ae4c222f0e182d7"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public Rubeus project."
        category = "TOOL"
        md5 = "66e0681a500c726ed52e5ea9423d2654"
        rev = 4

    strings:
        $typelibguid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}
rule Trojan_Raw_Generic_4
{
    meta:
        id = "4kgh5lUikxFJvhYLvhvewc"
        fingerprint = "v1_sha256_8ffd23631c1a9d1abe6695858ec34d61261b3b3f097be94372f3f34e46e7211e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "f41074be5b423afb02a74bc74222e35d"
        rev = 1

    strings:
        $s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
        $s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }
    condition:
        uint16(0) != 0x5A4D and all of them
}
rule HackTool_Win32_AndrewSpecial_1
{
    meta:
        id = "3PH87UIFBNwihxImp8cuVx"
        fingerprint = "v1_sha256_529a49fb21250069111d03a174901dc2e1623ee2a1f446aae1bdb1579a227dd3"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "e89efa88e3fda86be48c0cc8f2ef7230"
        rev = 4

    strings:
        $dump = { 6A 00 68 FF FF 1F 00 FF 15 [4] 89 45 ?? 83 [2] 00 [1-50] 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 10 68 [4] FF 15 [4] 89 45 [10-70] 6A 00 6A 00 6A 00 6A 02 8B [2-4] 5? 8B [2-4] 5? 8B [2-4] 5? E8 [4-20] FF 15 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
        $shellcode_x86_inline = { C6 45 ?? B8 C6 45 ?? 3C C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 33 C6 45 ?? C9 C6 45 ?? 8D C6 45 ?? 54 C6 45 ?? 24 C6 45 ?? 04 C6 45 ?? 64 C6 45 ?? FF C6 45 ?? 15 C6 45 ?? C0 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 83 C6 45 ?? C4 C6 45 ?? 04 C6 45 ?? C2 C6 45 ?? 14 C6 45 ?? 00 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and $dump and any of ($shellcode*)
}
rule APT_Backdoor_Win_GORAT_3
{
    meta:
        id = "5T7fnNpjESOg9y0jI06Oc0"
        fingerprint = "v1_sha256_592745e9c67f7adf0cd48975ed1497211d8efeff29b52be1e2d082b9a648bb57"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule uses the same logic as FE_APT_Trojan_Win_GORAT_1_FEBeta with the addition of one check, to look for strings that are known to be in the Gorat implant when a certain cleaning script is not run against it."
        category = "TOOL"
        md5 = "995120b35db9d2f36d7d0ae0bfc9c10d"
        rev = 5

    strings:
        $dirty1 = "fireeye" ascii nocase wide
        $dirty2 = "kulinacs" ascii nocase wide
        $dirty3 = "RedFlare" ascii nocase wide
        $dirty4 = "gorat" ascii nocase wide
        $dirty5 = "flare" ascii nocase wide
        $go1 = "go.buildid" ascii wide
        $go2 = "Go build ID:" ascii wide
        $json1 = "json:\"pid\"" ascii wide
        $json2 = "json:\"key\"" ascii wide
        $json3 = "json:\"agent_time\"" ascii wide
        $json4 = "json:\"rid\"" ascii wide
        $json5 = "json:\"ports\"" ascii wide
        $json6 = "json:\"agent_platform\"" ascii wide
        $rat = "rat" ascii wide
        $str1 = "handleCommand" ascii wide
        $str2 = "sendBeacon" ascii wide
        $str3 = "rat.AgentVersion" ascii wide
        $str4 = "rat.Core" ascii wide
        $str5 = "rat/log" ascii wide
        $str6 = "rat/comms" ascii wide
        $str7 = "rat/modules" ascii wide
        $str8 = "murica" ascii wide
        $str9 = "master secret" ascii wide
        $str10 = "TaskID" ascii wide
        $str11 = "rat.New" ascii wide
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($json*) and all of ($str*) and #rat > 1000 and any of ($dirty*)
}
rule CredTheft_Win_EXCAVATOR_1
{
    meta:
        id = "29GTGDFfjmkUf1z07Pgy1V"
        fingerprint = "v1_sha256_bf4b776f34a1a9aa5438504f63a63ef452a747363de3b70cec52145d777055bd"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for the binary signature of the 'Inject' method found in the main Excavator PE."
        category = "TOOL"
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        rev = 4

    strings:
        $bytes1 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 20 01 00 00 48 8B 05 75 BF 01 00 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 8D 0D 12 A1 01 00 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 00 FF 15 CB 1F 01 00 48 85 C0 75 1B FF 15 80 1F 01 00 8B D0 48 8D 0D DF A0 01 00 E8 1A FF FF FF 33 C0 E9 B4 02 00 00 48 8D 15 D4 A0 01 00 48 89 9C 24 30 01 00 00 48 8B C8 FF 15 4B 1F 01 00 48 8B D8 48 85 C0 75 19 FF 15 45 1F 01 00 8B D0 48 8D 0D A4 A0 01 00 E8 DF FE FF FF E9 71 02 00 00 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 45 66 66 0F 1F 84 00 00 00 00 00 48 8B 4C 24 60 FF 15 4D 1F 01 00 3B C6 74 22 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 D1 EB 0A 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A0 01 00 48 8D 05 A6 C8 01 00 B9 C8 05 00 00 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 B2 FF 15 CC 1E 01 00 4C 8D 44 24 78 BA 0A 00 00 00 48 8B C8 FF 15 01 1E 01 00 85 C0 0F 84 66 01 00 00 48 8B 4C 24 78 48 8D 45 80 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 D8 1D 01 00 85 C0 0F 84 35 01 00 00 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 50 01 FF 15 5C 1E 01 00 FF 15 06 1E 01 00 4C 8B 44 24 68 33 D2 48 8B C8 FF 15 DE 1D 01 00 48 8B F8 48 85 C0 0F 84 FF 00 00 00 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 50 01 FF 15 25 1E 01 00 85 C0 0F 84 E2 00 00 00 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 6C 1D 01 00 85 C0 0F 84 B1 00 00 00 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C 8D 05 58 39 03 00 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 44 24 30 04 00 08 00 44 89 74 24 28 4C 89 74 24 20 FF 15 0C 1D 01 00 85 C0 74 65 48 8B 4C 24 70 8B 5D 98 FF 15 1A 1D 01 00 48 8B 4D 88 FF 15 10 1D 01 00 48 8B 4D 90 FF 15 06 1D 01 00 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 4E 1D 01 00 48 8B D8 48 85 C0 74 2B 48 8B C8 E8 4E 06 00 00 48 85 C0 74 1E BA FF FF FF FF 48 8B C8 FF 15 3B 1D 01 00 48 8B CB FF 15 CA 1C 01 00 B8 01 00 00 00 EB 24 FF 15 DD 1C 01 00 8B D0 48 8D 0D 58 9E 01 00 E8 77 FC FF FF 48 85 FF 74 09 48 8B CF FF 15 A9 1C 01 00 33 C0 48 8B 9C 24 30 01 00 00 48 8B 4D 10 48 33 CC E8 03 07 00 00 4C 8D 9C 24 20 01 00 00 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes2 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes3 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes4 = { 48 89 74 24 ?? 48 89 7C 24 ?? 4C 89 74 24 ?? 55 48 8D 6C 24 ?? 48 81 EC 20 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 ?? 48 8D 0D ?? ?? ?? ?? 4C 89 74 24 ?? 0F 11 45 ?? 41 8B FE 4C 89 74 24 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? FF 15 ?? ?? ?? ?? 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 66 0F 1F 84 00 ?? ?? 00 00 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 ?? 48 89 44 24 ?? 66 0F 6F 15 ?? ?? 01 00 48 8D 05 ?? ?? ?? ?? B9 C8 05 00 00 90 F3 0F 6F 40 ?? 48 8D 40 ?? 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? F3 0F 6F 40 ?? 66 0F EF C2 F3 0F 7F 40 ?? 48 83 E9 01 75 ?? FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 45 ?? 41 B9 02 00 00 00 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 02 00 00 00 41 8D 51 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 4C 8B 44 24 ?? 33 D2 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 48 8B C8 41 8D 50 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 ?? 4C 8D 4C 24 ?? 4C 89 74 24 ?? 33 D2 41 B8 00 00 02 00 48 C7 44 24 ?? 08 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D ?? 48 8D 45 ?? 48 89 44 24 ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 45 ?? 48 89 7D ?? 48 89 44 24 ?? 45 33 C9 4C 89 74 24 ?? 33 D2 4C 89 74 24 ?? C7 44 24 ?? 04 00 08 00 44 89 74 24 ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 8B 5D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA FF FF FF FF 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF 15 ?? ?? ?? ?? 33 C0 48 8B 9C 24 ?? ?? ?? ?? 48 8B 4D ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 73 ?? 49 8B 7B ?? 4D 8B 73 ?? 49 8B E3 5D C3 }
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and any of ($bytes*)
}
rule APT_Loader_Win64_REDFLARE_1
{
    meta:
        id = "2PrKqL1XJWUBrSdGrSEMhi"
        fingerprint = "v1_sha256_2cae245a6aa36dccc2228cccefdc4ca0eb278901f063e072a369000f67d73a55"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "f20824fa6e5c81e3804419f108445368"
        rev = 1

    strings:
        $alloc_n_load = { 41 B9 40 00 00 00 41 B8 00 30 00 00 33 C9 [1-10] FF 50 [4-80] F3 A4 [30-120] 48 6B C9 28 [3-20] 48 6B C9 28 }
        $const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Loader_Raw64_REDFLARE_1
{
    meta:
        id = "2S8NHuxkiT9C2wTOsJOx63"
        fingerprint = "v1_sha256_dac122ccece8a6dd35a5fe9d37860a612aa50ab469b79f4375dbe776f60c7b57"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "5e14f77f85fd9a5be46e7f04b8a144f5"
        rev = 1

    strings:
        $load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}
rule HackTool_MSIL_SHARPZEROLOGON_1
{
    meta:
        id = "5vQBjLBDOk9RVebH3bZDt7"
        fingerprint = "v1_sha256_ed6a9bef5c6ee03aff969b8765b284ace517f2e6a1ef114acb04cf094c69cfa5"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'sharpzerologon' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "15ce9a3c-4609-4184-87b2-e29fc5e2b770" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_CoreHound_1
{
    meta:
        id = "53m0VCYeURi3zPrtMJuDZm"
        fingerprint = "v1_sha256_b0f759709428d5c9404507a13259bf85cb8c405d38b807539098f7cc871023d8"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CoreHound' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "1fff2aee-a540-4613-94ee-4f208b30c599" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Loader_MSIL_NETAssemblyInject_1
{
    meta:
        id = "4tjS1wGBOmZ8lr8uCVXeaZ"
        fingerprint = "v1_sha256_9a43df9ee26a44f4db5c2d22fbc1a6c86c5af0c9d44a79c6627a4cc8cf31bb8d"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NET-Assembly-Inject' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "af09c8c3-b271-4c6c-8f48-d5f0e1d1cac6" ascii nocase wide
        $typelibguid1 = "c5e56650-dfb0-4cd9-8d06-51defdad5da1" ascii nocase wide
        $typelibguid2 = "e8fa7329-8074-4675-9588-d73f88a8b5b6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Hunting_GadgetToJScript_1
{
    meta:
        id = "23cZhSFg5KkvpZv7Yo8q7"
        fingerprint = "v1_sha256_a880c20e61376dacd4e3a04f2cf065f19067c29371180b1dec186172cadf9564"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule is looking for B64 offsets of LazyNetToJscriptLoader which is a namespace specific to the internal version of the GadgetToJScript tooling."
        category = "TOOL"
        md5 = "7af24305a409a2b8f83ece27bb0f7900"
        rev = 4

    strings:
        $s1 = "GF6eU5ldFRvSnNjcmlwdExvYWRl"
        $s2 = "henlOZXRUb0pzY3JpcHRMb2Fk"
        $s3 = "YXp5TmV0VG9Kc2NyaXB0TG9hZGV"
    condition:
        any of them
}
rule Trojan_MSIL_GORAT_Plugin_DOTNET_1
{
    meta:
        id = "1uq9LgHrhJDXKvAZa2JtDy"
        fingerprint = "v1_sha256_e979822273c6d1ccdfebd341c9e2cb1040fe34a04e8b41c024885063fd946ad5"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Plugin - .NET' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "cd9407d0-fc8d-41ed-832d-da94daa3e064" ascii nocase wide
        $typelibguid1 = "fc3daedf-1d01-4490-8032-b978079d8c2d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Trojan_Win_REDFLARE_1
{
    meta:
        id = "2BzJLOaoo9kLCfIlzldKmm"
        fingerprint = "v1_sha256_08ea2151418f7f75a8b138146c393a5ea85647320cc8e9fe1930d75871ab94bb"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "100d73b35f23b2fe84bf7cd37140bf4d,4e7e90c7147ee8aa01275894734f4492"
        rev = 3

    strings:
        $1 = "initialize" fullword
        $2 = "runCommand" fullword
        $3 = "stop" fullword
        $4 = "fini" fullword
        $5 = "VirtualAllocEx" fullword
        $6 = "WriteProcessMemory" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Dropper_Win64_MATRYOSHKA_1
{
    meta:
        id = "6JWGcBdOi6Io5j5V3AjzLT"
        fingerprint = "v1_sha256_23f811f8e9387ca6a1257a31af66de9739733e4728adba0a3e3f74b5e5c0a556"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "matryoshka_dropper.rs"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "edcd58ba5b1b87705e95089002312281"
        rev = 1

    strings:
        $sb1 = { 8D 8D [4] E8 [4] 49 89 D0 C6 [2-6] 01 C6 [2-6] 01 [0-8] C7 44 24 ?? 0E 00 00 00 4C 8D 0D [4] 48 8D 8D [4] 48 89 C2 E8 [4] C6 [2-6] 01 C6 [2-6] 01 48 89 E9 48 8D 95 [4] E8 [4] 83 [2] 01 0F 8? [4] 48 01 F3 48 29 F7 48 [2] 08 48 89 85 [4] C6 [2-6] 01 C6 [2-6] 01 C6 [2-6] 01 48 8D 8D [4] 48 89 DA 49 89 F8 E8 }
        $sb2 = { 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 68 00 00 00 48 8B [2] 48 8D [2] 48 89 [3] 48 89 [3] 0F 11 44 24 ?? C7 44 24 ?? 08 00 00 0C C7 44 24 ?? 00 00 00 00 31 ?? 48 89 ?? 31 ?? 45 31 ?? 45 31 ?? E8 [4] 83 F8 01 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_HackTool_MSIL_SHARPGOPHER_1
{
    meta:
        id = "7JVS1F2YtWMYa6QmUu39Yl"
        fingerprint = "v1_sha256_ac37f77440cb76d7dafa4c9b4130471ca6ca760f6d72691db9ebb8cbaaad0c58"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpgopher' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "83413a89-7f5f-4c3f-805d-f4692bc60173" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_KeeFarce_1
{
    meta:
        id = "6TNJVX3hdeP4IktH9lsE0i"
        fingerprint = "v1_sha256_8db86230849137608880dbe448737fc70068d308772e294cc69301b18ae10908"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeeFarce' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "17589ea6-fcc9-44bb-92ad-d5b3eea6af03" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Backdoor_Win_GORAT_1
{
    meta:
        id = "26fyDsRFy4dyMkO7cjC8e9"
        fingerprint = "v1_sha256_f6a0a923f64375e7ffdc080aec41db19a9e162405f1290ed0bbcce5a342bdadb"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This detects if a sample is less than 50KB and has a number of strings found in the Gorat shellcode (stage0 loader). The loader contains an embedded DLL (stage0.dll) that contains a number of unique strings. The 'Cookie' string found in this loader is important as this cookie is needed by the C2 server to download the Gorat implant (stage1 payload)."
        category = "TOOL"
        md5 = "66cdaa156e4d372cfa3dea0137850d20"
        rev = 4

    strings:
        $s1 = "httpComms.dll" ascii wide
        $s2 = "Cookie: SID1=%s" ascii wide
        $s3 = "Global\\" ascii wide
        $s4 = "stage0.dll" ascii wide
        $s5 = "runCommand" ascii wide
        $s6 = "getData" ascii wide
        $s7 = "initialize" ascii wide
        $s8 = "Windows NT %d.%d;" ascii wide
        $s9 = "!This program cannot be run in DOS mode." ascii wide
    condition:
        filesize < 50KB and all of them
}
rule APT_Dropper_Win_MATRYOSHKA_1
{
    meta:
        id = "1UzTAHs7FjvWYjACsqzb31"
        fingerprint = "v1_sha256_a7bf7599ec9b4b1d09a8c90b70ae565a9396fb31d449da3c1492d6fa336d9c5e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "matryoshka_dropper.rs"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "edcd58ba5b1b87705e95089002312281"
        rev = 1

    strings:
        $s1 = "\x00matryoshka.exe\x00"
        $s2 = "\x00Unable to write data\x00"
        $s3 = "\x00Error while spawning process. NTStatus: \x0a\x00"
        $s4 = "\x00.execmdstart/Cfailed to execute process\x00"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_Win_Generic_20
{
    meta:
        id = "Oy97y9PNzp0H15TrPKJEj"
        fingerprint = "v1_sha256_9611aed2b4e4278d40254cb5c4fe94a458cfa19f10e6fe888bc7ceb166669cc6"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "5125979110847d35a338caac6bff2aa8"
        rev = 1

    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_Win32_PGF_2
{
    meta:
        id = "2mHx1EYzENGj1UIjvKs6YQ"
        fingerprint = "v1_sha256_d69f3f31c4964fe933295563e08bdbb36abadd6611541b9ffa55b6829ced1d21"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "04eb45f8546e052fe348fda2425b058c"
        rev = 1

    strings:
        $sb1 = { 6A ?? FF 15 [4-16] 8A ?? 04 [0-16] 8B ?? 1C [0-64] 0F 10 ?? 66 0F EF C8 0F 11 [0-32] 30 [2] 8D [2] 4? 83 [2] 7? }
        $sb2 = { 8B ?? 08 [0-16] 6A 40 68 00 30 00 00 5? 6A 00 [0-32] FF 15 [4-32] 5? [0-16] E8 [4-64] C1 ?? 04 [0-32] 8A [2] 3? [2] 4? 3? ?? 24 ?? 7? }
        $sb3 = { 8B ?? 3C [0-16] 03 [1-64] 0F B? ?? 14 [0-32] 83 ?? 18 [0-32] 66 3? ?? 06 [4-32] 68 [4] 5? FF 15 [4-16] 85 C0 [2-32] 83 ?? 28 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_HackTool_MSIL_REDTEAMMATERIALS_1
{
    meta:
        id = "2crtwmSro5uFrqrR5W5Wft"
        fingerprint = "v1_sha256_ca54a1e8335c4256295fc643f5d31eae2e89f020dc7a9b571c4772edaad08022"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'red_team_materials' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "86c95a99-a2d6-4ebe-ad5f-9885b06eab12" ascii nocase wide
        $typelibguid1 = "e06f1411-c7f8-4538-bbb9-46c928732245" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Trojan_Win_REDFLARE_7
{
    meta:
        id = "5WyFUmUsSVH4bd5secxeLL"
        fingerprint = "v1_sha256_6d7822256ac1bef05304d3396df773e2b20a397311ad820d6ec5fe4cb6bdfbbc"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "e7beece34bdf67cbb8297833c5953669, 8025bcbe3cc81fc19021ad0fbc11cf9b"
        rev = 1

    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "NamedPipe"
        $named_pipe = { 88 13 00 00 [1-8] E8 03 00 00 [20-60] 00 00 00 00 [1-8] 00 00 00 00 [1-40] ( 6A 00 6A 00 6A 03 6A 00 6A 00 68 | 00 00 00 00 [1-6] 00 00 00 00 [1-6] 03 00 00 00 45 33 C? 45 33 C? BA ) 00 00 00 C0 [2-10] FF 15 [4-30] FF 15 [4-7] E7 00 00 00 [4-40] FF 15 [4] 85 C0 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Trojan_Win_REDFLARE_8
{
    meta:
        id = "5xInKUnu4fhygTcKDTcYAh"
        fingerprint = "v1_sha256_5b8a0402886daebefb995e7df0877d51727c5b8dc58eeb8ff16ceec5e7811a20"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
        rev = 1

    strings:
        $1 = "PSRunner.PSRunner" fullword
        $2 = "CorBindToRuntime" fullword
        $3 = "ReportEventW" fullword
        $4 = "InvokePS" fullword wide
        $5 = "runCommand" fullword
        $6 = "initialize" fullword
        $trap = { 03 40 00 80 E8 [4] CC }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Backdoor_Win_GORAT_5
{
    meta:
        id = "1u1n71Q9isTxkbGCR7Sqmv"
        fingerprint = "v1_sha256_67f85fb3bedfd18a1226c92318f387be3c7ff9566ca2d554c49cf62389482552"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "cdf58a48757010d9891c62940c439adb, a107850eb20a4bb3cc59dbd6861eaf0f"
        rev = 1

    strings:
        $1 = "comms.BeaconData" fullword
        $2 = "comms.CommandResponse" fullword
        $3 = "rat.BaseChannel" fullword
        $4 = "rat.Config" fullword
        $5 = "rat.Core" fullword
        $6 = "platforms.AgentPlatform" fullword
        $7 = "GetHostID" fullword
        $8 = "/rat/cmd/gorat_shared/dllmain.go" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_GPOHUNT_1
{
    meta:
        id = "1Rizt2D1ZOvvtqnfLIWC3"
        fingerprint = "v1_sha256_4b1f175dac123a6340494e2730d66c718478fb7618dc5611315992ed33e0f6c7"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'gpohunt' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "751a9270-2de0-4c81-9e29-872cd6378303" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_JUSTASK_1
{
    meta:
        id = "FHQ63AVWYl2ubCj7IeePZ"
        fingerprint = "v1_sha256_24d2f8e3838c4f02cd80644a396ce7cf105761d2feba54e39973564ca5e97571"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'justask' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "aa59be52-7845-4fed-9ea5-1ea49085d67a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Trojan_Win_REDFLARE_4
{
    meta:
        id = "6DRzWmMUsFJVlXVtHcSYNA"
        fingerprint = "v1_sha256_d027e98ad8fa6d03a49ceffd81fba6a621173e2dbabae652bee2f4e8489bb378"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "a8b5dcfea5e87bf0e95176daa243943d, 9dcb6424662941d746576e62712220aa"
        rev = 2

    strings:
        $s1 = "LogonUserW" fullword
        $s2 = "ImpersonateLoggedOnUser" fullword
        $s3 = "runCommand" fullword
        $user_logon = { 22 02 00 00 [1-10] 02 02 00 00 [0-4] E8 [4-40] ( 09 00 00 00 [1-10] 03 00 00 00 | 6A 03 6A 09 ) [4-30] FF 15 [4] 85 C0 7? }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_TITOSPECIAL_1
{
    meta:
        id = "2nxfDswixuRXFu28YfjeFf"
        fingerprint = "v1_sha256_6def0c667d38c1bad9233628e509bdcaed322e75be4ff3823b0f788c391e090c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 5

    strings:
        $ind_dump = { 1F 10 16 28 [2] 00 0A 6F [2] 00 0A [50-200] 18 19 18 73 [2] 00 0A 13 [1-4] 06 07 11 ?? 6F [2] 00 0A 18 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 }
        $ind_s1 = "NtReadVirtualMemory" fullword wide
        $ind_s2 = "WriteProcessMemory" fullword
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($ind*) and any of ($shellcode* )
}
rule Dropper_LNK_LNKSmasher_1
{
    meta:
        id = "2yeHt6RTTpsN1qSNnCWBPN"
        fingerprint = "v1_sha256_61d1ac67ac0d332ad842a522cbebe1b9af1482d58a210b50fb45209355c0aeeb"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The LNKSmasher project contains a prebuilt LNK file that has pieces added based on various configuration items. Because of this, several artifacts are present in every single LNK file generated by LNKSmasher, including the Drive Serial #, the File Droid GUID, and the GUID CLSID."
        category = "TOOL"
        md5 = "0a86d64c3b25aa45428e94b6e0be3e08"
        rev = 6

    strings:
        $drive_serial = { 12 F7 26 BE }
        $file_droid_guid = { BC 96 28 4F 0A 46 54 42 81 B8 9F 48 64 D7 E9 A5 }
        $guid_clsid = { E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D }
        $header = { 4C 00 00 00 01 14 02 }
    condition:
        $header at 0 and all of them
}
rule HackTool_MSIL_SharpSchtask_1
{
    meta:
        id = "3iwJSWFTVFNPgHZ6OQ2OXf"
        fingerprint = "v1_sha256_7437fde82920f4d015a7f149b58924baf6cb220c6f6857d9509e23795ff0811c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpSchtask' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "0a64a5f4-bdb6-443c-bdc7-f6f0bf5b5d6c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Controller_Linux_REDFLARE_1
{
    meta:
        id = "4UorU71o7TTngiBmFXQhu7"
        fingerprint = "v1_sha256_d6b0cc5f386da9bff8a8293f2b3857406044ab42f7c1bb23d5096052a3c42ce4"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        rev = 1

    strings:
        $1 = "/RedFlare/gorat_server"
        $2 = "RedFlare/sandals"
        $3 = "goratsvr.CommandResponse" fullword
        $4 = "goratsvr.CommandRequest" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}
rule APT_HackTool_MSIL_WMISPY_2
{
    meta:
        id = "1Q3Ps1vyQiOcR0tRf4x1CD"
        fingerprint = "v1_sha256_553fc1e536482a56b3228a5c9ebac843af9083e8ac864bf65c81b36a39ca5e5e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "wql searches"
        category = "TOOL"
        md5 = "3651f252d53d2f46040652788499d65a"
        rev = 4

    strings:
        $MSIL = "_CorExeMain"
        $str1 = "root\\cimv2" wide
        $str2 = "root\\standardcimv2" wide
        $str3 = "from MSFT_NetNeighbor" wide
        $str4 = "from Win32_NetworkLoginProfile" wide
        $str5 = "from Win32_IP4RouteTable" wide
        $str6 = "from Win32_DCOMApplication" wide
        $str7 = "from Win32_SystemDriver" wide
        $str8 = "from Win32_Share" wide
        $str9 = "from Win32_Process" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of ($str*)
}
rule HackTool_MSIL_SharPersist_2
{
    meta:
        id = "6SuzwkZ7FTqHPcJfGbAKG1"
        fingerprint = "v1_sha256_57387352f8fd08e8b859dffc1164d46370f248b337526c265634160010572a00"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
        rev = 1

    strings:
        $a1 = "SharPersist.lib"
        $a2 = "SharPersist.exe"
        $b1 = "ERROR: Invalid hotkey location option given." ascii wide
        $b2 = "ERROR: Invalid hotkey given." ascii wide
        $b3 = "ERROR: Keepass configuration file not found." ascii wide
        $b4 = "ERROR: Keepass configuration file was not found." ascii wide
        $b5 = "ERROR: That value already exists in:" ascii wide
        $b6 = "ERROR: Failed to delete hidden registry key." ascii wide
        $pdb1 = "\\SharPersist\\"
        $pdb2 = "\\SharPersist.pdb"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ((@pdb2[1] < @pdb1[1] + 50) or (1 of ($a*) and 2 of ($b*)))
}
rule APT_Loader_Win_MATRYOSHKA_1
{
    meta:
        id = "2QzJL279Z4FDdBxqLEnybO"
        fingerprint = "v1_sha256_8f762684ffd3984630bf41ededa78b8993b53b22591a59912cabfe635775de53"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "matryoshka_process_hollow.rs"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "44887551a47ae272d7873a354d24042d"
        rev = 1

    strings:
        $s1 = "ZwQueryInformationProcess" fullword
        $s2 = "WriteProcessMemory" fullword
        $s3 = "CreateProcessW" fullword
        $s4 = "WriteProcessMemory" fullword
        $s5 = "\x00Invalid NT Signature!\x00"
        $s6 = "\x00Error while creating and mapping section. NTStatus: "
        $s7 = "\x00Error no process information - NTSTATUS:"
        $s8 = "\x00Error while erasing pe header. NTStatus: "
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule Builder_MSIL_SinfulOffice_1
{
    meta:
        id = "1JwYrmyK1yNOsxAMI7dGex"
        fingerprint = "v1_sha256_b5d49a8720e4daa21e95ec66299daec42e65906017de886ea91f7bb6bfb04c77"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SinfulOffice' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "9940e18f-e3c7-450f-801a-07dd534ccb9a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Loader_MSIL_SharPy_1
{
    meta:
        id = "8mR6v1VnZhW8d9YPbpjTF"
        fingerprint = "v1_sha256_0f73fab3905b4961b8dbeb120d45a34a2383ecdaae0296f38e34f8b7ab4aeee8"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharPy' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "f6cf1d3b-3e43-4ecf-bb6d-6731610b4866" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_MSIL_WILDCHILD_1
{
    meta:
        id = "6sfpRcV82HwefNJof9ISCO"
        fingerprint = "v1_sha256_a600c3d127f77dc1f99160e4a242e005970de0abd1798296b6a351b968ca1350"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "6f04a93753ae3ae043203437832363c4"
        rev = 1

    strings:
        $s1 = "\x00QueueUserAPC\x00"
        $s2 = "\x00WriteProcessMemory\x00"
        $sb1 = { 6F [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 13 ?? 28 [2] 00 0A 28 [2] 00 0A 13 ?? 11 ?? 11 ?? 28 [2] 00 0A [0-16] 7B [2] 00 04 1? 20 [4] 28 [2] 00 0A 11 ?? 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 [0-16] 14 7E [2] 00 0A 7E [2] 00 0A 1? 20 04 00 08 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 [0-16] 7B [2] 00 04 7E [2] 00 0A [0-16] 8E ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 [4-120] 28 [2] 00 06 [0-80] 6F [2] 00 0A 6F [2] 00 0A 28 [2] 00 06 13 ?? 11 ?? 11 ?? 7E [2] 00 0A 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_Win_Generic_18
{
    meta:
        id = "7N778uYO8vH2bSEHHQFo3X"
        fingerprint = "v1_sha256_28c9497f646fcf3daf7007d7afd37971dd85382062c064173f13049ad419fef1"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "c74ebb6c238bbfaefd5b32d2bf7c7fcc"
        rev = 3

    strings:
        $s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "fread" fullword
        $si2 = "fwrite" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_MSIL_TRIMBISHOP_1
{
    meta:
        id = "1MLdOWtPe77jDsLHr9ir89"
        fingerprint = "v1_sha256_f020efff58c8b7761d700c662c422a9e1ffdf8fe5f6648e421b7c257e3b8d078"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1

    strings:
        $sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
        $sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@sb1[1] < @sb2[1]) and (all of ($ss*)) and (all of ($tb*))
}
rule APT_Loader_MSIL_TRIMBISHOP_2
{
    meta:
        id = "2Y1mMzbpeIeUsl2qqsPvWK"
        fingerprint = "v1_sha256_4cccfca0c06954105f762066741b6c35599a6c28df8b7c255a2659059169578f"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "c0598321d4ad4cf1219cc4f84bad4094"
        rev = 1

    strings:
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
        $ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
        $tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Backdoor_Win_DShell_3
{
    meta:
        id = "1Z3UY6XV4qFtRNuPCngnJg"
        fingerprint = "v1_sha256_1b2b35cdf222c433bfb1fd39bd322bf75a3cb0e5f12b4d0a12b48e7fc1166a64"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for strings specific to the D programming language in combination with sections of an integer array which contains the encoded payload found within DShell"
        category = "TOOL"
        md5 = "cf752e9cd2eccbda5b8e4c29ab5554b6"
        rev = 3

    strings:
        $dlang1 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang2 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang3 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang4 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang5 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang6 = "\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang7 = "\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang8 = "\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang9 = "\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang10 = "\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang11 = "Unexpected '\\n' when converting from type const(char)[] to type int" ascii wide
        $e0 = ",0,"
        $e1 = ",1,"
        $e2 = ",2,"
        $e3 = ",3,"
        $e4 = ",4,"
        $e5 = ",5,"
        $e6 = ",6,"
        $e7 = ",7,"
        $e8 = ",8,"
        $e9 = ",9,"
        $e10 = ",10,"
        $e11 = ",11,"
        $e12 = ",12,"
        $e13 = ",13,"
        $e14 = ",14,"
        $e15 = ",15,"
        $e16 = ",16,"
        $e17 = ",17,"
        $e18 = ",18,"
        $e19 = ",19,"
        $e20 = ",20,"
        $e21 = ",21,"
        $e22 = ",22,"
        $e23 = ",23,"
        $e24 = ",24,"
        $e25 = ",25,"
        $e26 = ",26,"
        $e27 = ",27,"
        $e28 = ",28,"
        $e29 = ",29,"
        $e30 = ",30,"
        $e31 = ",31,"
        $e32 = ",32,"
        $e33 = ",33,"
        $e34 = ",34,"
        $e35 = ",35,"
        $e36 = ",36,"
        $e37 = ",37,"
        $e38 = ",38,"
        $e39 = ",39,"
        $e40 = ",40,"
        $e41 = ",41,"
        $e42 = ",42,"
        $e43 = ",43,"
        $e44 = ",44,"
        $e45 = ",45,"
        $e46 = ",46,"
        $e47 = ",47,"
        $e48 = ",48,"
        $e49 = ",49,"
        $e50 = ",50,"
        $e51 = ",51,"
        $e52 = ",52,"
        $e53 = ",53,"
        $e54 = ",54,"
        $e55 = ",55,"
        $e56 = ",56,"
        $e57 = ",57,"
        $e58 = ",58,"
        $e59 = ",59,"
        $e60 = ",60,"
        $e61 = ",61,"
        $e62 = ",62,"
        $e63 = ",63,"
        $e64 = ",64,"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize > 500KB and filesize < 1500KB and 40 of ($e*) and 1 of ($dlang*)
}
rule APT_HackTool_MSIL_SHARPSTOMP_1
{
    meta:
        id = "6jmjvAgwgxNSSprHrXOlgX"
        fingerprint = "v1_sha256_af8aa0e87d8b6623a908fde5014f3849cd0ca20d5926c798be82ce4eab2668bb"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 3

    strings:
        $s0 = "mscoree.dll" fullword nocase
        $s1 = "timestompfile" fullword nocase
        $s2 = "sharpstomp" fullword nocase
        $s3 = "GetLastWriteTime" fullword
        $s4 = "SetLastWriteTime" fullword
        $s5 = "GetCreationTime" fullword
        $s6 = "SetCreationTime" fullword
        $s7 = "GetLastAccessTime" fullword
        $s8 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_SHARPPATCHCHECK_1
{
    meta:
        id = "4utUr7eYByesxwgMa3pO5r"
        fingerprint = "v1_sha256_dec6231b656eed1526d4f70fe1b9a476bfb06246f0a7c25f2687d8c68886d400"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharppatchcheck' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "528b8df5-6e5e-4f3b-b617-ac35ed2f8975" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SAFETYKATZ_4
{
    meta:
        id = "6ieoWQhNnqdMrJGAVuhGRq"
        fingerprint = "v1_sha256_a02b4acea691d485f427ed26487f2f601065901324a8dcd6cd8de9502d8cd897"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SafetyKatz project."
        category = "TOOL"
        md5 = "45736deb14f3a68e88b038183c23e597"
        rev = 3

    strings:
        $typelibguid1 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Backdoor_MacOS_GORAT_1
{
    meta:
        id = "5wlCtYvs8MzUXUFoIhGgAF"
        fingerprint = "v1_sha256_2df5f87d44968670511880d21ad184779d0561c7c426a5d6426bcefd0904a9b7"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule is looking for specific strings associated with network activity found within the MacOS generated variant of GORAT"
        category = "TOOL"
        md5 = "68acf11f5e456744262ff31beae58526"
        rev = 3

    strings:
        $s1 = "SID1=%s" ascii wide
        $s2 = "http/http.dylib" ascii wide
        $s3 = "Mozilla/" ascii wide
        $s4 = "User-Agent" ascii wide
        $s5 = "Cookie" ascii wide
    condition:
        ((uint32(0) == 0xBEBAFECA) or (uint32(0) == 0xFEEDFACE) or (uint32(0) == 0xFEEDFACF) or (uint32(0) == 0xCEFAEDFE)) and all of them
}
rule CredTheft_MSIL_ADPassHunt_2
{
    meta:
        id = "3K8gSL8yYQxY4dovjtoemM"
        fingerprint = "v1_sha256_e7282905a8baeaeb8ec156171fbf2bc4ac811facb80959a88394f4938a145cc1"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 1

    strings:
        $pdb1 = "\\ADPassHunt\\"
        $pdb2 = "\\ADPassHunt.pdb"
        $s1 = "Usage: .\\ADPassHunt.exe"
        $s2 = "[ADA] Searching for accounts with msSFU30Password attribute"
        $s3 = "[ADA] Searching for accounts with userpassword attribute"
        $s4 = "[GPP] Searching for passwords now"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ((@pdb2[1] < @pdb1[1] + 50) or 2 of ($s*))
}
rule APT_Loader_Win64_PGF_4
{
    meta:
        id = "35MoCldOoXuHAh5BQ4xoY6"
        fingerprint = "v1_sha256_fcc92674e58ec6418d7c709e3f3bc2e1ec859fe0cb444412964a978fb69f5234"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        rev = 1

    strings:
        $sb1 = { 41 B9 04 00 00 00 41 B8 00 10 00 00 BA [4] B9 00 00 00 00 [0-32] FF [1-24] 7? [1-150] 8B 45 [0-32] 44 0F B? ?? 8B [2-16] B? CD CC CC CC [0-16] C1 ?? 04 [0-16] C1 ?? 02 [0-16] C1 ?? 02 [0-16] 48 8? 05 [4-32] 31 [1-4] 88 }
        $sb2 = { C? 45 ?? 48 [0-32] B8 [0-64] FF [0-32] E0 [0-32] 41 B8 40 00 00 00 BA 0C 00 00 00 48 8B [2] 48 8B [2-32] FF [1-16] 48 89 10 8B 55 ?? 89 ?? 08 48 8B [2] 48 8D ?? 02 48 8B 45 18 48 89 02 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Loader_Win32_PGF_4
{
    meta:
        id = "7e7ek53V56AiS8SF8yHEbS"
        fingerprint = "v1_sha256_4256bfd3713f330d76cad9d1ddbba91e588dbca2e2b6842e9482525805ddc1e8"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "4414953fa397a41156f6fa4f9462d207"
        rev = 1

    strings:
        $sb1 = { C7 44 24 0C 04 00 00 00 C7 44 24 08 00 10 00 00 [4-32] C7 04 24 00 00 00 00 [0-32] FF [1-16] 89 45 ?? 83 7D ?? 00 [2-150] 0F B? ?? 8B [2] B? CD CC CC CC 89 ?? F7 ?? C1 ?? 04 89 ?? C1 ?? 02 [0-32] 0F B? [5-32] 3? [1-16] 88 }
        $sb2 = { C? 45 ?? B8 [0-4] C? 45 ?? 00 [0-64] FF [0-32] E0 [0-32] C7 44 24 08 40 00 00 00 [0-32] C7 44 24 04 07 00 00 00 [0-32] FF [1-64] 89 ?? 0F B? [2-3] 89 ?? 04 0F B? [2] 88 ?? 06 8B ?? 08 8D ?? 01 8B 45 0C }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule CredTheft_MSIL_ADPassHunt_1
{
    meta:
        id = "51k3vZhIBAHml5OJNXAMbB"
        fingerprint = "v1_sha256_85c7c147d6bf5b7cb417ff2910a3e7ab3be5e8a3651758c07f8f0ed42b5964d8"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public ADPassHunt project."
        category = "TOOL"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 4

    strings:
        $typelibguid = "15745B9E-A059-4AF1-A0D8-863E349CD85D" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}
rule HackTool_MSIL_GETDOMAINPASSWORDPOLICY_1
{
    meta:
        id = "249hwctBfCPGv5nHy56kgd"
        fingerprint = "v1_sha256_6b2ea3ebfea2c87f16052f4a43b64eb2d595c2dd4a64d45dfce1642668dcf602"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the recon utility 'getdomainpasswordpolicy' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 4

    strings:
        $typelibguid0 = "a5da1897-29aa-45f4-a924-561804276f08" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SharPivot_1
{
    meta:
        id = "1DTLjWL4llmwxCnxqd3kqA"
        fingerprint = "v1_sha256_1c71b9641e30c9764f3503e49f8f85472d7e62384c8dd2b420c4fa2b2fccda4f"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3

    strings:
        $s2 = { 73 ?? 00 00 0A 0A 06 1F ?? 1F ?? 6F ?? 00 00 0A 0B 73 ?? 00 00 0A 0C 16 13 04 2B 5E 23 [8] 06 6F ?? 00 00 0A 5A 23 [8] 58 28 ?? 00 00 0A 28 ?? 00 00 0A 28 ?? 00 00 0A }
        $s3 = "cmd_rpc" wide
        $s4 = "costura"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_Win32_PGF_3
{
    meta:
        id = "I3rISQ6aWJY7WzIL4RFPv"
        fingerprint = "v1_sha256_24d2caad1d740ccbff0cf111a05ecad20ed06f311d530d8de86050d916da32ce"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "PGF payload, generated rule based on symfunc/c02594972dbab6d489b46c5dee059e66. Identifies dllmain_hook x86 payloads."
        category = "TOOL"
        md5 = "4414953fa397a41156f6fa4f9462d207"
        rev = 4

    strings:
        $cond1 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF 90 EE 01 6D C7 85 30 F9 FF FF 6C FE 01 6D 8D 85 34 F9 FF FF 89 28 BA CC 19 00 6D 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BB A6 00 00 A1 48 A1 05 6D C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B8 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 56 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 DF B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 52 0B 01 00 A1 4C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 51 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 EF AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 82 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 84 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 2C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 0C 40 05 6D A1 5C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 18 40 05 6D 89 04 24 A1 60 A1 05 6D FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 54 A1 05 6D FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 9C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 00 6D 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 00 6D 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 5D BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 48 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A0 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 FD BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 75 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 76 A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond2 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF B0 EF 3D 6A C7 85 30 F9 FF FF 8C FF 3D 6A 8D 85 34 F9 FF FF 89 28 BA F4 1A 3C 6A 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 B3 A6 00 00 A1 64 A1 41 6A C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B0 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 4E 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 D7 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 4A 0B 01 00 A1 68 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 49 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 E7 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 7A FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 7C AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 62 40 41 6A A1 78 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 6E 40 41 6A 89 04 24 A1 7C A1 41 6A FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 41 6A FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 3C 6A 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 3C 6A 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 55 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 40 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 98 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 F5 BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 6D A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 6E A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond3 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF F0 EF D5 63 C7 85 30 F9 FF FF CC FF D5 63 8D 85 34 F9 FF FF 89 28 BA 28 1B D4 63 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BF A6 00 00 A1 64 A1 D9 63 C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 BC AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 5A 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 E3 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 56 0B 01 00 A1 68 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 55 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 F3 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 86 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 88 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 7E 40 D9 63 A1 7C A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 8A 40 D9 63 89 04 24 A1 80 A1 D9 63 FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 D9 63 FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 D4 63 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 D4 63 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 61 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 4C 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A4 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 01 BC 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 79 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 7A A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond4 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? 90 EE 01 6D C7 85 ?? ?? ?? ?? 6C FE 01 6D 8D 85 ?? ?? ?? ?? 89 28 BA CC 19 00 6D 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 0C 40 05 6D A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 18 40 05 6D 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 00 6D 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 00 6D 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
        $cond5 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? B0 EF 3D 6A C7 85 ?? ?? ?? ?? 8C FF 3D 6A 8D 85 ?? ?? ?? ?? 89 28 BA F4 1A 3C 6A 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 62 40 41 6A A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 6E 40 41 6A 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 3C 6A 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 3C 6A 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
        $cond6 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? F0 EF D5 63 C7 85 ?? ?? ?? ?? CC FF D5 63 8D 85 ?? ?? ?? ?? 89 28 BA 28 1B D4 63 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 7E 40 D9 63 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 8A 40 D9 63 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 D4 63 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 D4 63 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and any of them
}
rule APT_Loader_Win32_REDFLARE_2
{
    meta:
        id = "2ZpaQ0t3CeVytYpRwnuYJu"
        fingerprint = "v1_sha256_98dfb71adbde4f8965e612c19f0965d8fa95805825569290fdf72eb1d86cfb70"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "4e7e90c7147ee8aa01275894734f4492"
        rev = 1

    strings:
        $inject = { 83 F8 01 [4-50] 6A 00 6A 00 68 04 00 00 08 6A 00 6A 00 6A 00 6A 00 5? [10-70] FF 15 [4] 85 C0 [1-20] 6A 04 68 00 10 00 00 5? 6A 00 5? [1-10] FF 15 [4-8] 85 C0 [1-20] 5? 5? 5? 8B [1-4] 5? 5? FF 15 [4] 85 C0 [1-20] 6A 20 [4-20] FF 15 [4] 85 C0 [1-40] 01 00 01 00 [2-20] FF 15 [4] 85 C0 [1-30] FF 15 [4] 85 C0 [1-20] FF 15 [4] 83 F8 FF }
        $s1 = "ResumeThread"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_HackTool_MSIL_SHARPSTOMP_2
{
    meta:
        id = "5BlV1r9vPMxFyrm9zUWAB8"
        fingerprint = "v1_sha256_4ed1553f12c607792d7d4e7026ecb36231cd417a06eba8b2925c2c643436b5fe"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 3

    strings:
        $f0 = "mscoree.dll" fullword nocase
        $s0 = { 06 72 [4] 6F [4] 2C ?? 06 72 [4] 6F [4] 2D ?? 72 [4] 28 [4] 28 [4] 2A }
        $s1 = { 02 28 [4] 0A 02 28 [4] 0B 02 28 [4] 0C 72 [4] 28 [4] 72 }
        $s2 = { 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 72 }
        $s3 = "SetCreationTime" fullword
        $s4 = "GetLastAccessTime" fullword
        $s5 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_MSIL_NetshShellCodeRunner_1
{
    meta:
        id = "2FNID8BlPl9Dz7PZdUgWF0"
        fingerprint = "v1_sha256_97f6475a9d42697f633e06a9b04a85021ca4920145eb4af257d71b431448f0e9"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NetshShellCodeRunner' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "49c045bc-59bb-4a00-85c3-4beb59b2ee12" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SharPivot_4
{
    meta:
        id = "1JwGdXpDaaTs9qxZSnrKFz"
        fingerprint = "v1_sha256_7ef883148926d5786861e5e81b1e645aa2e3ca06bd663f2b5f32e04b5852a218"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPivot project."
        category = "TOOL"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3

    strings:
        $typelibguid1 = "44B83A69-349F-4A3E-8328-A45132A70D62" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Backdoor_Win_GoRat_Memory
{
    meta:
        id = "6h8yl1zGvtjuO6TzSqgFDZ"
        fingerprint = "v1_sha256_88272e59325d106f96d6b6f1d57daf968823c1e760067dee0334c66c521ce8c2"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "Identifies GoRat malware in memory based on strings."
        category = "TOOL"
        md5 = "3b926b5762e13ceec7ac3a61e85c93bb"
        rev = 1

    strings:
        $murica = "murica" fullword
        $rat1 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
        $rat2 = "rat.(*Core).generateBeacon" fullword
        $rat3 = "rat.gJitter" fullword
        $rat4 = "rat/comms.(*protectedChannel).SendCmdResponse" fullword
        $rat5 = "rat/modules/filemgmt.(*acquire).NewCommandExecution" fullword
        $rat6 = "rat/modules/latlisten.(*latlistensrv).handleCmd" fullword
        $rat7 = "rat/modules/netsweeper.(*netsweeperRunner).runSweep" fullword
        $rat8 = "rat/modules/netsweeper.(*Pinger).listen" fullword
        $rat9 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
        $rat10 = "rat/platforms/win/dyloader.(*memoryLoader).ExecutePluginFunction" fullword
        $rat11 = "rat/platforms/win/modules/namedpipe.(*dummy).Open" fullword
        $winblows = "rat/platforms/win.(*winblows).GetStage" fullword
    condition:
        $winblows or #murica > 10 or 3 of ($rat*)
}
rule Loader_MSIL_AllTheThings_1
{
    meta:
        id = "3NzL4cYpDAAgSJGFKqNUwy"
        fingerprint = "v1_sha256_e3058095f2a49f8c0f78cb392024795367609b04c1da80210ab8d72c6613ee71"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'AllTheThings' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "542ccc64-c4c3-4c03-abcd-199a11b26754" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win64_PGF_1
{
    meta:
        id = "3EmFOFBKBVxfmi7Xeezlh"
        fingerprint = "v1_sha256_2e84d614c34b0b7f93fa70fa3312f22e3ff23f2abd33b2e19c00dd6cba7dcfdc"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "2b686a8b83f8e1d8b455976ae70dab6e"
        rev = 1

    strings:
        $sb1 = { B9 14 00 00 00 FF 15 [4-32] 0F B6 ?? 04 [0-32] F3 A4 [0-64] 0F B6 [2-3] 0F B6 [2-3] 33 [0-32] 88 [1-9] EB }
        $sb2 = { 41 B8 00 30 00 00 [0-32] FF 15 [8-64] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [1-64] FF ( D? | 5? ) }
        $sb3 = { 48 89 4C 24 08 [4-64] 48 63 48 3C [0-32] 48 03 C1 [0-64] 0F B7 48 14 [0-64] 48 8D 44 08 18 [8-64] 0F B7 40 06 [2-32] 48 6B C0 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Trojan_Win_REDFLARE_5
{
    meta:
        id = "5fkuApwkrMc63iqPGm6H2p"
        fingerprint = "v1_sha256_ab38e5ebded026829672941709797b40f8e13fb244b6a8ed3545de4358f727b8"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
        rev = 3

    strings:
        $s1 = "AdjustTokenPrivileges" fullword
        $s2 = "LookupPrivilegeValueW" fullword
        $s3 = "ImpersonateLoggedOnUser" fullword
        $s4 = "runCommand" fullword
        $steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule CredTheft_MSIL_TitoSpecial_1
{
    meta:
        id = "dMiZVVPVBJG2FJi2b1zoe"
        fingerprint = "v1_sha256_4ac9a5ede4aea5d73545b459eb635f87ce08ba521afa48b76d2cfa94f1379226"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have the strings of various method names in the TitoSpecial code."
        category = "TOOL"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 4

    strings:
        $str1 = "Minidump" ascii wide
        $str2 = "dumpType" ascii wide
        $str3 = "WriteProcessMemory" ascii wide
        $str4 = "bInheritHandle" ascii wide
        $str5 = "GetProcessById" ascii wide
        $str6 = "SafeHandle" ascii wide
        $str7 = "BeginInvoke" ascii wide
        $str8 = "EndInvoke" ascii wide
        $str9 = "ConsoleApplication1" ascii wide
        $str10 = "getOSInfo" ascii wide
        $str11 = "OpenProcess" ascii wide
        $str12 = "LoadLibrary" ascii wide
        $str13 = "GetProcAddress" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($str*)
}
rule Builder_MSIL_G2JS_1
{
    meta:
        id = "4vhmZ53S3Ut8wpPkrFVTAF"
        fingerprint = "v1_sha256_487d8e8deef218412f241d99ce32b63bfeb3568d23048b9dd4afff8f401bfea5"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the Gadget2JScript project."
        category = "TOOL"
        md5 = "fa255fdc88ab656ad9bc383f9b322a76"
        rev = 2

    strings:
        $typelibguid1 = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Loader_Win32_DShell_2
{
    meta:
        id = "1nNAZpKcwrnYeOnPo2YymX"
        fingerprint = "v1_sha256_958ff45add46c0a43e839e8007c1d9296ee89ddd8c045b8ec6b031b225207a6c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "590d98bb74879b52b97d8a158af912af"
        rev = 2

    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
        $ss4 = "C:\\Users\\config.ini" fullword
        $ss5 = "Invalid config file" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule HackTool_MSIL_SharPivot_3
{
    meta:
        id = "1whC7sxqdmX5Cs1O8tvElp"
        fingerprint = "v1_sha256_ecf13e47e409efd68b508735a84be6a1627f5b0c0cea6b90434fc9ba5b1d8cf5"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have the strings of various method names in the SharPivot code."
        category = "TOOL"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3

    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "SharPivot" ascii wide
        $str2 = "ParseArgs" ascii wide
        $str3 = "GenRandomString" ascii wide
        $str4 = "ScheduledTaskExists" ascii wide
        $str5 = "ServiceExists" ascii wide
        $str6 = "lpPassword" ascii wide
        $str7 = "execute" ascii wide
        $str8 = "WinRM" ascii wide
        $str9 = "SchtaskMod" ascii wide
        $str10 = "PoisonHandler" ascii wide
        $str11 = "SCShell" ascii wide
        $str12 = "SchtaskMod" ascii wide
        $str13 = "ServiceHijack" ascii wide
        $str14 = "commandArg" ascii wide
        $str15 = "payloadPath" ascii wide
        $str16 = "Schtask" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
rule APT_HackTool_MSIL_FLUFFY_2
{
    meta:
        id = "1H7dpsSzpcObexeds74i7t"
        fingerprint = "v1_sha256_872ab717668375a49d6c7b1927a680747b405c0198fe4fc6f43ccc562870eb37"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-04"
        date_modified = "2020-12-04"
        md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
        rev = 1

    strings:
        $s1 = "\x00Asktgt\x00"
        $s2 = "\x00Kerberoast\x00"
        $s3 = "\x00HarvestCommand\x00"
        $s4 = "\x00EnumerateTickets\x00"
        $s5 = "[*] Action: " wide
        $s6 = "\x00Fluffy.Commands\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_FLUFFY_1
{
    meta:
        id = "7bQuzTS3HY8tCULWoOXGl6"
        fingerprint = "v1_sha256_4d91c96ab7b628e88f79ee193612acc959448fe2220ef54371f5f5c6e7305d86"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-04"
        date_modified = "2020-12-04"
        md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
        rev = 1

    strings:
        $sb1 = { 0E ?? 1? 72 [4] 28 [2] 00 06 [0-16] 28 [2] 00 0A [2-80] 1F 58 0? [0-32] 28 [2] 00 06 [2-32] 1? 28 [2] 00 06 0? 0? 6F [2] 00 06 [2-4] 1F 0B }
        $sb2 = { 73 [2] 00 06 13 ?? 11 ?? 11 ?? 7D [2] 00 04 11 ?? 73 [2] 00 0A 7D [2] 00 04 0E ?? 2D ?? 11 ?? 7B [2] 00 04 72 [4] 28 [2] 00 0A [2-32] 0? 28 [2] 00 0A [2-16] 11 ?? 7B [2] 00 04 0? 28 [2] 00 0A 1? 28 [2] 00 0A [2-32] 7E [2] 00 0A [0-32] FE 15 [2] 00 02 [0-16] 7D [2] 00 04 28 [2] 00 06 [2-32] 7B [2] 00 04 7D [2] 00 04 [2-32] 7C [2] 00 04 FE 15 [2] 00 02 [0-16] 11 ?? 8C [2] 00 02 28 [2] 00 0A 28 [2] 00 0A [2-80] 8C [2] 00 02 28 [2] 00 0A 12 ?? 12 ?? 12 ?? 28 [2] 00 06 }
        $ss1 = "\x00Fluffy\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule HackTool_MSIL_SEATBELT_1
{
    meta:
        id = "7EvQjOvz8ivNl4TD5XodTa"
        fingerprint = "v1_sha256_4248e5561ef60e725c23efc89c899d6fc8be5bf2142f700fb70daecd72c30dd8"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have regex and format strings found in the public tool SeatBelt. Due to the nature of the regex and format strings used for detection, this rule should detect custom variants of the SeatBelt project."
        category = "TOOL"
        md5 = "848837b83865f3854801be1f25cb9f4d"
        rev = 3

    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "{ Process = {0}, Path = {1}, CommandLine = {2} }" ascii nocase wide
        $str2 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii nocase wide
        $str3 = "LogonId=\"(\\d+)\"" ascii nocase wide
        $str4 = "{0}.{1}.{2}.{3}" ascii nocase wide
        $str5 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii nocase wide
        $str6 = "*[System/EventID={0}]" ascii nocase wide
        $str7 = "*[System[TimeCreated[@SystemTime >= '{" ascii nocase wide
        $str8 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii nocase wide
        $str9 = "{0}" ascii nocase wide
        $str10 = "{0,-23}" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
rule HackTool_MSIL_INVEIGHZERO_1
{
    meta:
        id = "1YlRKsLTZdZpsOrFrdEFh0"
        fingerprint = "v1_sha256_5d10557a83dae9508469fe87f4c0c91beec4d2812856eee461a82d5dbb89aa35"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'inveighzero' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "113ae281-d1e5-42e7-9cc2-12d30757baf1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Loader_MSIL_RURALBISHOP_1
{
    meta:
        id = "67KzZQXlie837hcmLMWaqG"
        fingerprint = "v1_sha256_f2244c6761639c1162a77a5e82296903c3cc21fbf46d262c779c5e4d6a2ef937"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1

    strings:
        $sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
        $sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@sb1[1] < @sb2[1]) and (all of ($ss*)) and (all of ($tb*))
}
rule Loader_MSIL_RURALBISHOP_2
{
    meta:
        id = "7bEw8RbDjZMt08KQaweRNR"
        fingerprint = "v1_sha256_0467532d643cf0200c6561b0724c884230892bf59db163c311b7d4f8acbb63d6"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1

    strings:
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
        $ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
        $tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule HackTool_MSIL_PrepShellcode_1
{
    meta:
        id = "1DcmJHX4p8STnrphSj9qjT"
        fingerprint = "v1_sha256_aedae87d84275f6589c982c04175ddc0aee3e4f3ae959ced4b4e2294675522e6"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'PrepShellcode' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "d16ed275-70d5-4ae5-8ce7-d249f967616c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Downloader_Win32_REDFLARE_1
{
    meta:
        id = "1469EEmgrjYVMxGP2tGGnd"
        fingerprint = "v1_sha256_a340a2a732a9b1aa74ca9d84009a88d1b14b6a03140a859384c0d6e745e4a90a"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "05b99d438dac63a5a993cea37c036673"
        rev = 1

    strings:
        $const = "Cookie: SID1=%s" fullword
        $http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [1-10] 6A 00 8B [1-8] 5? 6A 00 6A 00 6A 00 8B [1-8] 5? 68 [4] 8B [1-8] 5? FF 15 [4-40] 6A 14 E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule Loader_MSIL_WMIRunner_1
{
    meta:
        id = "6Rlizlytkh5OiQrCbOT3X4"
        fingerprint = "v1_sha256_49d21756a4f0b29909c4b0fa9f3a98dd0480f9401923032de4b3920814b85f29"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIRunner' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "6cc61995-9fd5-4649-b3cc-6f001d60ceda" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SharpStomp_1
{
    meta:
        id = "62kFgeLw9letDaHWbQTfmL"
        fingerprint = "v1_sha256_fd0a3d046734d48be74d9a74f27570468550d21911c54ca82c81a1d64e9fdd17"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharpStomp project."
        category = "TOOL"
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 4

    strings:
        $typelibguid1 = "41f35e79-2034-496a-8c82-86443164ada2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule Tool_MSIL_SharpGrep_1
{
    meta:
        id = "778kp5ZdATyxQcEKoBLGnS"
        fingerprint = "v1_sha256_c22bfc50b3ab3c4082006aad3c3c89684cffe1e429b001b0bb08758856a47d04"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGrep' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "f65d75b5-a2a6-488f-b745-e67fc075f445" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Dropper_HTA_WildChild_1
{
    meta:
        id = "5FIm7XAvNhU0SKqjrFtG2P"
        fingerprint = "v1_sha256_60c1d53b8a43b9b7518f3260a4d61c6806641ee894a2a331a3a0a2ea0aff9d99"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for strings present in unobfuscated HTAs generated by the WildChild builder."
        category = "TOOL"
        md5 = "3e61ca5057633459e96897f79970a46d"
        rev = 5

    strings:
        $s1 = "processpath" ascii wide
        $s2 = "v4.0.30319" ascii wide
        $s3 = "v2.0.50727" ascii wide
        $s4 = "COMPLUS_Version" ascii wide
        $s5 = "FromBase64Transform" ascii wide
        $s6 = "MemoryStream" ascii wide
        $s7 = "entry_class" ascii wide
        $s8 = "DynamicInvoke" ascii wide
        $s9 = "Sendoff" ascii wide
        $script_header = "<script language=" ascii wide
    condition:
        $script_header at 0 and all of ($s*)
}
rule APT_Builder_PY_REDFLARE_2
{
    meta:
        id = "66gqle70e9LPXWXe8dgSVQ"
        fingerprint = "v1_sha256_675390e944a95156ad33ca783c90fdea9610cdc2e8c5c53e0c0fa213149b4714"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "4410e95de247d7f1ab649aa640ee86fb"
        rev = 1

    strings:
        $1 = "<510sxxII"
        $2 = "0x43,0x00,0x3a,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,"
        $3 = "parsePluginOutput"
    condition:
        all of them and #2 == 2
}
rule APT_Loader_Win32_DShell_3
{
    meta:
        id = "6BVaGabHNwD0PMbRJ4Xju0"
        fingerprint = "v1_sha256_ec2a8b0abc6cb6d1861199b892fbe84782b42babb08e3ea203d10ab17ff7a20a"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        rev = 1

    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_Trojan_Linux_REDFLARE_1
{
    meta:
        id = "7FvMnsnldxDsjYFI0pkPzY"
        fingerprint = "v1_sha256_282f11c4c86d88d05f11e92f5483701d9a54c2dd39f21316cd271aa78a338d0f"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        rev = 1

    strings:
        $s1 = "find_applet_by_name" fullword
        $s2 = "bb_basename" fullword
        $s3 = "hk_printf_chk" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}
rule Loader_MSIL_WildChild_1
{
    meta:
        id = "4m4bXKJLGBgaNMPJwprly6"
        fingerprint = "v1_sha256_e4320e33770613542182518ec787e4ccbb32f83c8afca5ec957d4846e6f4eb04"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the WildChild project."
        category = "TOOL"
        md5 = "7e6bc0ed11c2532b2ae7060327457812"
        rev = 4

    strings:
        $typelibguid1 = "2e71d5ff-ece4-4006-9e98-37bb724a7780" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule MSIL_Launcher_DUEDLLIGENCE_1
{
    meta:
        id = "4ePM86ELnpvlBM1LysbAL0"
        fingerprint = "v1_sha256_bd6abaa909f0c776d81ed1115e875888336661c91df3881f4f3ea5dd27e115f8"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'DUEDLLIGENCE' project."
        category = "TOOL"
        md5 = "a91bf61cc18705be2288a0f6f125068f"
        rev = 1

    strings:
        $typelibguid0 = "73948912-cebd-48ed-85e2-85fcd1d4f560" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Backdoor_Win_GORAT_2
{
    meta:
        id = "3S1Aw1FLJ8TUUTJgaAl5yJ"
        fingerprint = "v1_sha256_8efc904498386d89879766a5021148a250f639bc328df12a34cfc8d620df6f6c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "Verifies that the sample is a Windows PE that is less than 10MB in size and has the Go build ID strings. Then checks for various strings known to be in the Gorat implant including strings used in C2 json, names of methods, and the unique string 'murica' used in C2 comms. A check is done to ensure the string 'rat' appears in the binary over 1000 times as it is the name of the project used by the implant and is present well over 2000 times."
        category = "TOOL"
        md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
        rev = 7

    strings:
        $go1 = "go.buildid" ascii wide
        $go2 = "Go build ID:" ascii wide
        $json1 = "json:\"pid\"" ascii wide
        $json2 = "json:\"key\"" ascii wide
        $json3 = "json:\"agent_time\"" ascii wide
        $json4 = "json:\"rid\"" ascii wide
        $json5 = "json:\"ports\"" ascii wide
        $json6 = "json:\"agent_platform\"" ascii wide
        $rat = "rat" ascii wide
        $str1 = "handleCommand" ascii wide
        $str2 = "sendBeacon" ascii wide
        $str3 = "rat.AgentVersion" ascii wide
        $str4 = "rat.Core" ascii wide
        $str5 = "rat/log" ascii wide
        $str6 = "rat/comms" ascii wide
        $str7 = "rat/modules" ascii wide
        $str8 = "murica" ascii wide
        $str9 = "master secret" ascii wide
        $str10 = "TaskID" ascii wide
        $str11 = "rat.New" ascii wide
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($json*) and all of ($str*) and #rat > 1000
}
rule APT_Loader_Win64_REDFLARE_2
{
    meta:
        id = "7YqgeYI453iyAFjwhMhqPx"
        fingerprint = "v1_sha256_9fad845ed963fae46ac7ddc44407d5f6ed0a061f6a106764b9f912ef718279b4"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "100d73b35f23b2fe84bf7cd37140bf4d"
        rev = 1

    strings:
        $alloc = { 45 8B C0 33 D2 [2-6] 00 10 00 00 [2-6] 04 00 00 00 [1-6] FF 15 [4-60] FF 15 [4] 85 C0 [4-40] 20 00 00 00 [4-40] FF 15 [4] 85 C0 }
        $inject = { 83 F8 01 [2-20] 33 C0 45 33 C9 [3-10] 45 33 C0 [3-10] 33 D2 [30-100] FF 15 [4] 85 C0 [20-100] 01 00 10 00 [0-10] FF 15 [4] 85 C0 [4-30] FF 15 [4] 85 C0 [2-20] FF 15 [4] 83 F8 FF }
        $s1 = "ResumeThread" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule HackTool_MSIL_SharPersist_1
{
    meta:
        id = "71wXN6MJL2Qt2vPTcvlg5Z"
        fingerprint = "v1_sha256_cf480026c31b522850e25ba2d7986773d9c664242a2667ecd33151621c98c91e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPersist project."
        category = "TOOL"
        md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
        rev = 1

    strings:
        $typelibguid1 = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Backdoor_Win_DShell_1
{
    meta:
        id = "jYVXR1q0Q0tK9YaOEqdTv"
        fingerprint = "v1_sha256_18f959af6456dd256a4cbe54eecd3fec7ad5c7651198277010f23c6eb3657fb9"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule is looking for sections of an integer array which contains the encoded payload along with a selection of Windows functions that are present within a DShell payload"
        category = "TOOL"
        md5 = "152fc2320790aa16ef9b6126f47c3cca"
        rev = 4

    strings:
        $e0 = ",0,"
        $e1 = ",1,"
        $e2 = ",2,"
        $e3 = ",3,"
        $e4 = ",4,"
        $e5 = ",5,"
        $e6 = ",6,"
        $e7 = ",7,"
        $e8 = ",8,"
        $e9 = ",9,"
        $e10 = ",10,"
        $e11 = ",11,"
        $e12 = ",12,"
        $e13 = ",13,"
        $e14 = ",14,"
        $e15 = ",15,"
        $e16 = ",16,"
        $e17 = ",17,"
        $e18 = ",18,"
        $e19 = ",19,"
        $e20 = ",20,"
        $e21 = ",21,"
        $e22 = ",22,"
        $e23 = ",23,"
        $e24 = ",24,"
        $e25 = ",25,"
        $e26 = ",26,"
        $e27 = ",27,"
        $e28 = ",28,"
        $e29 = ",29,"
        $e30 = ",30,"
        $e31 = ",31,"
        $e32 = ",32,"
        $e33 = ",33,"
        $e34 = ",34,"
        $e35 = ",35,"
        $e36 = ",36,"
        $e37 = ",37,"
        $e38 = ",38,"
        $e39 = ",39,"
        $e40 = ",40,"
        $e41 = ",41,"
        $e42 = ",42,"
        $e43 = ",43,"
        $e44 = ",44,"
        $e45 = ",45,"
        $e46 = ",46,"
        $e47 = ",47,"
        $e48 = ",48,"
        $e49 = ",49,"
        $e50 = ",50,"
        $e51 = ",51,"
        $e52 = ",52,"
        $e53 = ",53,"
        $e54 = ",54,"
        $e55 = ",55,"
        $e56 = ",56,"
        $e57 = ",57,"
        $e58 = ",58,"
        $e59 = ",59,"
        $e60 = ",60,"
        $e61 = ",61,"
        $e62 = ",62,"
        $e63 = ",63,"
        $e64 = ",64,"
        $s1 = "GetACP"
        $s2 = "GetOEMCP"
        $s3 = "GetCPInfo"
        $s4 = "WriteConsoleA"
        $s5 = "FindFirstFileA"
        $s6 = "FileTimeToDosDateTime"
        $s7 = "FindNextFileA"
        $s8 = "GetStringTypeA"
        $s9 = "GetFileType"
        $s10 = "CreateFileA"
        $s11 = "GlobalAlloc"
        $s12 = "GlobalFree"
        $s13 = "GetTickCount"
        $s14 = "GetProcessHeap"
        $s15 = "UnhandledExceptionFilter"
        $s16 = "ExitProcess"
        $s17 = "GetModuleFileNameA"
        $s18 = "LCMapStringA"
        $s19 = "GetLocalTime"
        $s20 = "CreateThread"
        $s21 = "ExitThread"
        $s22 = "SetConsoleCtrlHandler"
        $s23 = "FreeEnvironmentStringsA"
        $s24 = "GetVersion"
        $s25 = "GetEnvironmentStrings"
        $s26 = "SetHandleCount"
        $s27 = "SetFilePointer"
        $s28 = "DeleteFileA"
        $s29 = "HeapAlloc"
        $s30 = "HeapReAlloc"
        $s31 = "HeapFree"
        $s32 = "GetCommandLineA"
        $s33 = "GetThreadContext"
        $s34 = "SuspendThread"
        $s35 = "FindFirstFileW"
        $s36 = "FindNextFileW"
        $s37 = "FindClose"
        $s38 = "CreateSemaphoreA"
        $s39 = "ReleaseSemaphore"
        $s40 = "ExpandEnvironmentStringsW"
        $s41 = "lstrlenW"
        $s42 = "GetModuleHandleA"
        $s43 = "GetEnvironmentVariableA"
        $s44 = "RtlCaptureContext"
        $s45 = "GlobalMemoryStatus"
        $s46 = "VirtualAlloc"
        $s47 = "Sleep"
        $s48 = "SystemTimeToTzSpecificLocalTime"
        $s49 = "TzSpecificLocalTimeToSystemTime"
        $s50 = "GetTimeZoneInformation"
        $s51 = "TryEnterCriticalSection"
        $s52 = "LoadLibraryA"
        $s53 = "VirtualFree"
        $s54 = "GetExitCodeThread"
        $s55 = "WaitForSingleObject"
        $s56 = "ResumeThread"
        $s57 = "DuplicateHandle"
        $s58 = "GetCurrentProcess"
        $s59 = "GetCurrentThread"
        $s60 = "GetCurrentThreadId"
        $s61 = "InitializeCriticalSection"
        $s62 = "DeleteCriticalSection"
        $s63 = "SwitchToThread"
        $s64 = "LeaveCriticalSection"
        $s65 = "EnterCriticalSection"
        $s66 = "FormatMessageW"
        $s67 = "SetLastError"
        $s68 = "GetEnvironmentVariableW"
        $s69 = "FreeEnvironmentStringsW"
        $s70 = "GetEnvironmentStringsW"
        $s71 = "SetEnvironmentVariableW"
        $s72 = "GetSystemInfo"
        $s73 = "QueryPerformanceFrequency"
        $s74 = "QueryPerformanceCounter"
        $s75 = "CreateProcessW"
        $s76 = "GetStdHandle"
        $s77 = "GetHandleInformation"
        $s78 = "SetHandleInformation"
        $s79 = "WriteFile"
        $s80 = "GetConsoleOutputCP"
        $s81 = "FreeLibrary"
        $s82 = "GetConsoleScreenBufferInfo"
        $s83 = "MultiByteToWideChar"
        $s84 = "RaiseException"
        $s85 = "RtlUnwind"
        $s86 = "GetCurrentDirectoryW"
        $s87 = "IsDebuggerPresent"
        $s88 = "LocalFree"
        $s89 = "WideCharToMultiByte"
        $s90 = "GetCommandLineW"
        $s91 = "ReadFile"
        $s92 = "GetFileSize"
        $s93 = "CloseHandle"
        $s94 = "CreateFileW"
        $s95 = "LoadLibraryW"
        $s96 = "GetProcAddress"
        $s97 = "GetFileAttributesW"
        $s98 = "GetLastError"
        $s99 = "CommandLineToArgvW"
        $s100 = "MessageBoxA"
        $s101 = "RegEnumValueW"
        $s102 = "RegEnumKeyExW"
        $s103 = "RegDeleteValueW"
        $s104 = "RegFlushKey"
        $s105 = "RegQueryInfoKeyW"
        $s106 = "RegDeleteKeyW"
        $s107 = "RegQueryValueExW"
        $s108 = "RegSetValueExW"
        $s109 = "RegOpenKeyW"
        $s110 = "RegOpenKeyExW"
        $s111 = "RegCreateKeyExW"
        $s112 = "RegCloseKey"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize > 500KB and 105 of ($s*) and $s112 in (3000..4000) and 40 of ($e*)
}
rule APT_Backdoor_Win_GORAT_4
{
    meta:
        id = "4CkkbBnBnlZpucQv2OuZCw"
        fingerprint = "v1_sha256_ec201614cb91fae9d7c89febfa22dfd6ba7f353e0eeb0b2fec6c8d887992e79e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "Verifies that the sample is a Windows PE that is less than 10MB in size and exports numerous functions that are known to be exported by the Gorat implant. This is done in an effort to provide detection for packed samples that may not have other strings but will need to replicate exports to maintain functionality."
        category = "TOOL"
        md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
        rev = 8

    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and pe.exports("MemoryCallEntryPoint") and pe.exports("MemoryDefaultAlloc") and pe.exports("MemoryDefaultFree") and pe.exports("MemoryDefaultFreeLibrary") and pe.exports("MemoryDefaultGetProcAddress") and pe.exports("MemoryDefaultLoadLibrary") and pe.exports("MemoryFindResource") and pe.exports("MemoryFindResourceEx") and pe.exports("MemoryFreeLibrary") and pe.exports("MemoryGetProcAddress") and pe.exports("MemoryLoadLibrary") and pe.exports("MemoryLoadLibraryEx") and pe.exports("MemoryLoadResource") and pe.exports("MemoryLoadString") and pe.exports("MemoryLoadStringEx") and pe.exports("MemorySizeofResource") and pe.exports("callback") and pe.exports("crosscall2") and pe.exports("crosscall_386")
}
rule APT_HackTool_MSIL_SHARPNFS_1
{
    meta:
        id = "ecCXel14LPqiwKJjTn3n1"
        fingerprint = "v1_sha256_e7f9883376b153849970599d9ecc308882eb86a67834cfd8ab06b44539346125"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnfs' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "9f67ebe3-fc9b-40f2-8a18-5940cfed44cf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule CredTheft_MSIL_CredSnatcher_1
{
    meta:
        id = "5pz4ycmAEc3DXiwgkJ5zFF"
        fingerprint = "v1_sha256_2c86be1bcf29bcb2c167f9248dee0ab4a5a5c6740fb1f18784ee2e380176df91"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CredSnatcher' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "370b4d21-09d0-433f-b7e4-4ebdd79948ec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SEATBELT_2
{
    meta:
        id = "kkMaQdKUuLzDADPeprA31"
        fingerprint = "v1_sha256_e48474c5025fd88e3c2824e1e943ff56cde0ea05984aad0249ccf73caa6d4a36"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SeatBelt project."
        category = "TOOL"
        md5 = "9f401176a9dd18fa2b5b90b4a2aa1356"
        rev = 3

    strings:
        $typelibguid1 = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Loader_Win32_DShell_1
{
    meta:
        id = "6xHxvKzN0DZxilmXj8IWPK"
        fingerprint = "v1_sha256_79643f9c252765647d80f6fe1ee7bb698fbc6a6c3a0ff1fd819a09bff031907c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        rev = 1

    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $sb2 = { FF 7? 0C B? [4-16] FF 7? 08 5? [0-12] E8 [4] 84 C0 74 05 B? 01 00 00 00 [0-16] 80 F2 01 0F 84 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_Loader_Win32_PGF_1
{
    meta:
        id = "ZcbOWNrcg6ln3C4LMCCO1"
        fingerprint = "v1_sha256_d3fb0bd7b678b19ee2e0e846f4e13e4ce7e2629ecda123f34ef52f2af42d2a8e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "383161e4deaf7eb2ebeda2c5e9c3204c"
        rev = 1

    strings:
        $sb1 = { 6A ?? FF 15 [4-32] 8A ?? 04 [0-32] 8B ?? 89 ?? 8B [2] 89 [2] 8B [2] 89 ?? 08 8B [2] 89 [2] 8B [2] 89 [2-64] 8B [5] 83 ?? 01 89 [5] 83 [5-32] 0F B6 [1-2] 0F B6 [1-2] 33 [1-16] 88 ?? EB }
        $sb2 = { 6A 40 [0-32] 68 00 30 00 00 [0-32] 6A 00 [0-16] FF 15 [4-32] 89 45 [4-64] E8 [4-32] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [2-64] FF ( D? | 55 ) }
        $sb3 = { 8B ?? 08 03 ?? 3C [2-32] 0F B? ?? 14 [0-32] 8D [2] 18 [2-64] 0F B? ?? 06 [3-64] 6B ?? 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_HackTool_MSIL_SHARPDACL_1
{
    meta:
        id = "7QKDZlR66kZYMNWo51aVhx"
        fingerprint = "v1_sha256_5f44ec5ddded18fb3a9132b469b2fe7ccbffb3f907325485f0f72fe3d6bbfa23"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdacl' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "b3c17fb5-5d5a-4b14-af3c-87a9aa941457" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_SHARPZIPLIBZIPPER_1
{
    meta:
        id = "1gAr9b9dSjxWMsIPZx2x3q"
        fingerprint = "v1_sha256_19354edb91a0d79fdf79437f7247bcf155514db40340af91a3320b556dc2e4c2"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpziplibzipper' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "485ba350-59c4-4932-a4c1-c96ffec511ef" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Downloader_Win64_REDFLARE_1
{
    meta:
        id = "6N3QYdHO707BQHMjgJcN4X"
        fingerprint = "v1_sha256_1b9bece6083403615841c752eac48fd20095e918d6e175563dd122be2885d875"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1"
        rev = 2

    strings:
        $const = "Cookie: SID1=%s" fullword
        $http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [6-20] 00 00 00 00 [6-20] 00 00 00 00 [2-10] 00 00 00 00 45 33 C9 [4-20] 48 8D 15 [4] 48 8B 0D [4] FF 15 [4-50] B9 14 00 00 00 E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Loader_Win64_MATRYOSHKA_1
{
    meta:
        id = "38JJCrpzMX6ntcrXJRIeqG"
        fingerprint = "v1_sha256_46e5480dc95ce8b9d8385c2e44a50b21629301535b93833c13cc3db319ac15dd"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "matryoshka_process_hollow.rs"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "44887551a47ae272d7873a354d24042d"
        rev = 1

    strings:
        $sb1 = { 48 8B 45 ?? 48 89 85 [0-64] C7 45 ?? 00 00 00 00 31 ?? E8 [4-64] BA 00 10 00 00 [0-32] 41 B8 04 00 00 00 E8 [4] 83 F8 01 [2-32] BA [4] E8 }
        $sb2 = { E8 [4] 83 F8 01 [2-64] 41 B9 00 10 00 00 [0-32] E8 [4] 83 F8 01 [2-32] 3D 4D 5A 00 00 [0-32] 48 63 ?? 3C [0-32] 50 45 00 00 [4-64] 0F B7 [2] 18 81 ?? 0B 01 00 00 [2-32] 81 ?? 0B 02 00 00 [2-32] 8B [2] 28 }
        $sb3 = { 66 C7 45 ?? 48 B8 48 C7 45 ?? 00 00 00 00 66 C7 45 ?? FF E0 [0-64] 41 B9 40 00 00 00 [0-32] E8 [4] 83 F8 01 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule HackTool_MSIL_WMIspy_1
{
    meta:
        id = "1WE04xNMb3P0kH6XjfeP4t"
        fingerprint = "v1_sha256_a5a9f7c7a7bfe474e8b21306ea220b4d476832f3ad4fafdd8967a2250d15a701"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIspy' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "5ee2bca3-01ad-489b-ab1b-bda7962e06bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Trojan_Win_REDFLARE_3
{
    meta:
        id = "2DKH9iVX3SyzG5lAEAZ07h"
        fingerprint = "v1_sha256_ee104bc145686a134e4d6d620dae7d1dacff7645d47f1a8d7a212327352b8e87"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "9ccda4d7511009d5572ef2f8597fba4e,ece07daca53dd0a7c23dacabf50f56f1"
        rev = 1

    strings:
        $calc_image_size = { 28 00 00 00 [2-30] 83 E2 1F [4-20] C1 F8 05 [0-8] 0F AF C? [0-30] C1 E0 02 }
        $str1 = "CreateCompatibleBitmap" fullword
        $str2 = "BitBlt" fullword
        $str3 = "runCommand" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_Win_PGF_1
{
    meta:
        id = "3aybeIaMFpRvQrCk1XdSPv"
        fingerprint = "v1_sha256_a0c51ff1e029072dfccb13f6237b554502775a57dce132aacb1cf20b1c4410a0"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "PDB string used in some PGF DLL samples"
        category = "TOOL"
        md5 = "013c7708f1343d684e3571453261b586"
        rev = 6

    strings:
        $pdb1 = /RSDS[\x00-\xFF]{20}c:\\source\\dllconfig-master\\dllsource[\x00-\xFF]{0,500}\.pdb\x00/ nocase
        $pdb2 = /RSDS[\x00-\xFF]{20}C:\\Users\\Developer\\Source[\x00-\xFF]{0,500}\Release\\DllSource\.pdb\x00/ nocase
        $pdb3 = /RSDS[\x00-\xFF]{20}q:\\objchk_win7_amd64\\amd64\\init\.pdb\x00/ nocase
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and any of them
}
rule APT_HackTool_MSIL_SHARPDNS_1
{
    meta:
        id = "23rJ3QwnBHkKpuah3IVIBQ"
        fingerprint = "v1_sha256_bab36f9b1532c3b24c2aea2907006820ed7cf1c90dae7a8138962e14ac9eff55"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdns' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "d888cec8-7562-40e9-9c76-2bb9e43bb634" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Loader_MSIL_TrimBishop_1
{
    meta:
        id = "6MRRShg5VLnn2gGHFvrHW"
        fingerprint = "v1_sha256_018e87542301db22c384fda2709e8d49711c0fa041d1ef591f98ee7a70dbb677"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have the string 'msg' more than 60 times as well as numerous function names unique to or used by the TrimBishop tool. All strings found in RuralBishop are reversed in TrimBishop and stored in a variable with the format 'msg##'. With the exception of 'msg', 'DTrim', and 'ReverseString' the other strings referenced in this rule may be shared with RuralBishop."
        category = "TOOL"
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        rev = 3

    strings:
        $msg = "msg" ascii wide
        $msil = "_CorExeMain" ascii wide
        $str1 = "RuralBishop" ascii wide
        $str2 = "KnightKingside" ascii wide
        $str3 = "ReadShellcode" ascii wide
        $str4 = "ReverseString" ascii wide
        $str5 = "DTrim" ascii wide
        $str6 = "QueensGambit" ascii wide
        $str7 = "Messages" ascii wide
        $str8 = "NtQueueApcThread" ascii wide
        $str9 = "NtAlertResumeThread" ascii wide
        $str10 = "NtQueryInformationThread" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and #msg > 60 and all of ($str*)
}
rule Loader_Win_Generic_17
{
    meta:
        id = "7RVDsLBIEQHucIUmCNxTph"
        fingerprint = "v1_sha256_5c20472c3af0c5b8c825671b12763900d6a711695ed04661b33cbf442422348d"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "562ecbba043552d59a0f23f61cea0983"
        rev = 3

    strings:
        $s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
        $s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
        $si1 = "fread" fullword
        $si2 = "fwrite" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_Win64_PGF_3
{
    meta:
        id = "1JQWnq2V36HUOXMsaQ0llb"
        fingerprint = "v1_sha256_fd82bdec54a76eed12cc8820ef39899f31ea6df21d905530a0d53770b3d9901b"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "PGF payload, generated rule based on symfunc/8a2f2236fdfaa3583ab89076025c6269. Identifies dllmain_hook x64 payloads."
        category = "TOOL"
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        rev = 4

    strings:
        $cond1 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 80 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 5A B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 E9 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AC 96 01 00 48 8D 45 AF 48 89 C1 E8 F0 FE 00 00 48 8B 05 25 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6B B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 AA B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 61 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 4F B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 20 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 0E C8 05 00 48 8B 05 69 8A 06 00 FF D0 48 8D 15 0A C8 05 00 48 89 C1 48 8B 05 5E 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 19 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 01 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 E0 F9 FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 87 F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CB 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 37 FC 00 00 48 89 D8 48 89 C1 E8 4C AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9A 9C 01 00 48 89 D8 48 89 C1 E8 2F AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond2 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 ?? ?? ?? ?? FF D0 48 89 C1 48 8D 85 ?? ?? ?? ?? 41 B8 04 01 00 00 48 89 C2 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8D 4D ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 49 89 C8 48 89 C1 E8 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 89 C2 B9 08 00 00 00 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 38 04 00 00 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 48 8D 85 ?? ?? ?? ?? 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 41 B8 00 00 00 00 48 89 C1 E8 ?? ?? ?? ?? 48 83 F8 FF 0F 95 C0 84 C0 74 ?? 48 8B 85 ?? ?? ?? ?? 48 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? EB ?? 48 8B 45 ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 48 8D 15 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 89 45 ?? 48 89 E8 48 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 C7 45 ?? 00 00 00 00 48 8B 55 ?? 48 8B 85 ?? ?? ?? ?? 48 39 C2 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 73 ?? 48 8B 45 ?? 48 8B 00 48 8B 55 ?? 48 81 C2 00 10 00 00 48 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 8B 4D ?? 48 8B 55 ?? 48 01 CA 48 39 D0 0F 83 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 8B 45 ?? 48 8B 00 48 8D 95 ?? ?? ?? ?? 41 B8 30 00 00 00 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 48 8B 45 ?? 48 8B 00 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 00 00 00 00 EB ?? 90 EB ?? 90 48 83 45 ?? 08 E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 48 63 D0 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 89 C2 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 01 00 00 00 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 83 FB 01 EB ?? 48 89 C3 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond3 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 C1 7C 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 33 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 B2 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 75 96 01 00 48 8D 45 AF 48 89 C1 E8 B9 FE 00 00 48 8B 05 66 7C 06 00 FF D0 89 C2 B9 08 00 00 00 E8 3C B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 83 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 2A F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 28 B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 69 7B 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 11 B9 05 00 48 8B 05 A2 7B 06 00 FF D0 48 8D 15 0D B9 05 00 48 89 C1 48 8B 05 97 7B 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 5A 7B 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 22 7B 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 59 FB FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 00 FB FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 94 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 00 FC 00 00 48 89 D8 48 89 C1 E8 45 AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 63 9C 01 00 48 89 D8 48 89 C1 E8 28 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond4 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 D3 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 65 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 EC FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AF 96 01 00 48 8D 45 AF 48 89 C1 E8 F3 FE 00 00 48 8B 05 78 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6E B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 B5 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 64 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 5A B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 73 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 45 C8 05 00 48 8B 05 B4 8A 06 00 FF D0 48 8D 15 41 C8 05 00 48 89 C1 48 8B 05 A9 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 6C 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 54 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 33 FA FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 DA F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CE 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 3A FC 00 00 48 89 D8 48 89 C1 E8 4F AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9D 9C 01 00 48 89 D8 48 89 C1 E8 32 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and any of them
}
rule HackTool_PY_ImpacketObfuscation_1
{
    meta:
        id = "5jBvbR0N3hfa5sv0OJxy0A"
        fingerprint = "v1_sha256_45a4c0426b29b8c8bede9c4e8292131da7e756d48fc3ac4a07d08fd52383d21e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "smbexec"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "0b1e512afe24c31531d6db6b47bac8ee"
        rev = 1

    strings:
        $s1 = "class CMDEXEC" nocase
        $s2 = "class RemoteShell" nocase
        $s3 = "self.services_names"
        $s4 = "import random"
        $s6 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]%CoMSpEC%[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
        $s7 = /self\.__serviceName[\x09\x20]{0,32}=[\x09\x20]{0,32}self\.services_names\[random\.randint\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}len\(self\.services_names\)[\x09\x20]{0,32}-[\x09\x20]{0,32}1\)\]/
    condition:
        all of them
}
rule APT_HackTool_Win64_EXCAVATOR_2
{
    meta:
        id = "4frD3I1usxRUKbY74OxRcD"
        fingerprint = "v1_sha256_14263c17323cd78df10f7f101bd7a9c74f7818b34a2e42125d45205067399381"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "4fd62068e591cbd6f413e1c2b8f75442"
        rev = 1

    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { C7 [2-5] FD 03 00 AC 4C 8D 4D ?? 41 B8 1F 00 10 00 8B [2-5] 48 8B 4D ?? E8 [4] 89 [2-5] 83 [2-5] 00 74 ?? 48 8B 4D ?? FF 15 [4] 33 C0 E9 [4] 41 B8 10 00 00 00 33 D2 48 8D 8D [4] E8 [4] 48 8D 05 [4] 48 89 85 [4] 48 C7 85 [8] 48 C7 44 24 30 00 00 00 00 C7 44 24 28 80 00 00 00 C7 44 24 20 01 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4] 48 89 85 [4] 48 83 BD [4] FF 75 ?? 48 8B 4D ?? FF 15 [4] 33 C0 EB [0-17] 48 8D [5] 48 89 ?? 24 30 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 41 B9 02 00 00 00 4C 8B 85 [4] 8B [1-5] 48 8B 4D ?? E8 }
        $enable_dbg_pri = { 4C 8D 45 ?? 48 8D 15 [4] 33 C9 FF 15 [4] 85 C0 0F 84 [4] C7 45 ?? 01 00 00 00 B8 0C 00 00 00 48 6B C0 00 48 8B 4D ?? 48 89 4C 05 ?? B8 0C 00 00 00 48 6B C0 00 C7 44 05 ?? 02 00 00 00 FF 15 [4] 4C 8D 45 ?? BA 20 00 00 00 48 8B C8 FF 15 [4] 85 C0 74 ?? 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 45 ?? 33 D2 48 8B 4D ?? FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}
rule APT_Loader_Raw32_REDFLARE_1
{
    meta:
        id = "5hrcMvkKjwC6BRHj0lJP4F"
        fingerprint = "v1_sha256_05ed89bd82600b4d5ef01ece2e0a9bd84e968988fd2bda1bab4ec316a9a9906b"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "4022baddfda3858a57c9cbb0d49f6f86"
        rev = 1

    strings:
        $load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}
rule APT_Loader_Win64_PGF_2
{
    meta:
        id = "5ugWYOmBxwDDnWXd1QQSLw"
        fingerprint = "v1_sha256_074f6d9ad78ecd4dd8e3d0b5c8b0f61a48374f3935b85c4222305b207b447ec7"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "4326a7e863928ffbb5f6bdf63bb9126e"
        rev = 2

    strings:
        $sb1 = { B9 [4] FF 15 [4-32] 8B ?? 1C [0-16] 0F B? ?? 04 [0-64] F3 0F 6F 00 [0-64] 66 0F EF C8 [0-64] F3 0F 7F 08 [0-64] 30 ?? 48 8D 40 01 48 83 ?? 01 7? }
        $sb2 = { 44 8B ?? 08 [0-32] 41 B8 00 30 00 00 [0-16] FF 15 [4-32] 48 8B C8 [0-16] E8 [4-64] 4D 8D 49 01 [0-32] C1 ?? 04 [0-64] 0F B? [2-16] 41 30 ?? FF 45 3? ?? 7? }
        $sb3 = { 63 ?? 3C [0-16] 03 [1-32] 0F B? ?? 14 [0-16] 8D ?? 18 [0-16] 03 [1-16] 66 ?? 3B ?? 06 7? [1-64] 48 8D 15 [4-32] FF 15 [4-16] 85 C0 [2-32] 41 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_HackTool_MSIL_SHARPTEMPLATE_1
{
    meta:
        id = "5GoSoj969GjLs3LjUZklnY"
        fingerprint = "v1_sha256_9746c1ab7b945d311c53fbdf95993d255369e06b23a3279c9f2e8a4df73ab63c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharptemplate' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "e9e452d4-9e58-44ff-ba2d-01b158dda9bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_MODIFIEDSHARPVIEW_1
{
    meta:
        id = "2adyTR8DsW1XXFSl4KRwUM"
        fingerprint = "v1_sha256_a47c48da998243fab92665649fb9d6ecc6ac32e1fd884c2c0d5ccecb05290c10"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'modifiedsharpview' project."
        category = "TOOL"
        md5 = "db0eaad52465d5a2b86fdd6a6aa869a5"
        rev = 3

    strings:
        $typelibguid0 = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win32_PGF_5
{
    meta:
        id = "1L01jDVLeoaLV2mDgPMm0Z"
        fingerprint = "v1_sha256_dfff615a1d329cf181294f7b0a32c11a21d66ff8a6aa6b9fcd183c9738369623"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "PGF payload, generated rule based on symfunc/a86b004b5005c0bcdbd48177b5bac7b8"
        category = "TOOL"
        md5 = "8c91a27bbdbe9fb0877daccd28bd7bb5"
        rev = 3

    strings:
        $cond1 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 10 30 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 5C 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 00 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
        $cond2 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 20 33 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 58 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 2C 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
        $cond3 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 68 03 01 00 00 6A 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 ?? 00 00 00 00 C6 45 ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 6A 01 6A 00 8D 8D ?? ?? ?? ?? 51 6A 00 68 9C 10 00 10 8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 ?? 6A 14 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 ?? 8B 45 ?? 8A 48 ?? 88 4D ?? 8B 55 ?? 83 C2 0C 8B 45 ?? 8B 0A 89 08 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 52 ?? 89 50 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 85 ?? ?? ?? ?? 83 C0 01 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 14 7D ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 11 0F B6 45 ?? 33 D0 8B 4D ?? 03 8D ?? ?? ?? ?? 88 11 EB ?? 8B 55 ?? 8B 42 ?? 89 45 ?? 6A 40 68 00 30 00 00 8B 4D ?? 51 6A 00 FF 15 ?? ?? ?? ?? 89 45 ?? 8B 55 ?? 52 8B 45 ?? 83 C0 20 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 83 C2 01 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 45 ?? 73 ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 09 8B 85 ?? ?? ?? ?? 99 BE 14 00 00 00 F7 FE 8B 45 ?? 0F B6 14 10 33 CA 8B 45 ?? 03 85 ?? ?? ?? ?? 88 08 EB ?? 8B 4D ?? 89 4D ?? FF 55 ?? 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }
        $cond4 = { 8B FF 55 8B EC 81 EC 3? ?1 ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 E0 56 C7 45 F8 ?? ?? ?? ?? C6 85 D8 FE FF FF ?? 68 ?? ?? ?? ?? 6A ?? 8D 85 D9 FE FF FF 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 F4 ?? ?? ?? ?? C6 45 E7 ?? C7 45 E8 ?? ?? ?? ?? C7 45 EC ?? ?? ?? ?? C7 45 FC ?? ?? ?? ?? C7 45 F? ?? ?? ?? ?0 6A ?? 6A ?? 8D 8D D8 FE FF FF 51 6A ?? 68 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 F8 6A ?? FF ?? ?? ?? ?? ?? 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 ?? ?? 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF ?? ?? ?? ?? EB ?? 8B 85 D4 FE FF FF 83 C? ?1 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D ?? 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB ?? 8B 55 F8 8B 42 08 89 45 FC 6A ?? 68 ?? ?? ?? ?? 8B 4D FC 51 6A ?? FF ?? ?? ?? ?? ?? 89 45 EC 8B 55 FC 52 8B 45 F8 83 ?? ?? 50 8B 4D EC 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 D0 FE FF FF ?? ?? ?? ?? EB ?? 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 ?? 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE ?? ?? ?? ?? F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB ?? 8B 4D EC 89 4D F0 FF ?? ?? 5E 8B 4D E0 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and any of them
}
rule APT_HackTool_MSIL_DNSOVERHTTPS_C2_1
{
    meta:
        id = "7BjAp4zBeBdGGyCnXbfqDQ"
        fingerprint = "v1_sha256_a482161bbd8e249977f28466ff1381d4693495f8b8ccd9183ae4fde1ec1471eb"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'DoHC2' External C2 project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
        $typelibguid1 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_LUALOADER_1
{
    meta:
        id = "6hRMkdSwmrqcItCuFn04Zh"
        fingerprint = "v1_sha256_7e9f9836ec91aa66c8779588cfceff718487f0cb5048d17538c947aba687a4cf"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'lualoader' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "8b546b49-2b2c-4577-a323-76dc713fe2ea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_PXELOOT_2
{
    meta:
        id = "2h6KowB8nif4eOK63df2Be"
        fingerprint = "v1_sha256_f3770b2b9543e8ed7fdb0d2bc4a71ebe8649157d7130a4369fb5a0c52589acd2"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for .NET PE files that have the strings of various method names in the PXE And Loot code."
        category = "TOOL"
        md5 = "d93100fe60c342e9e3b13150fd91c7d8"
        rev = 5

    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "PXE" ascii nocase wide
        $str2 = "InvestigateRPC" ascii nocase wide
        $str3 = "DhcpRecon" ascii nocase wide
        $str4 = "UnMountWim" ascii nocase wide
        $str5 = "remote WIM image" ascii nocase wide
        $str6 = "DISMWrapper" ascii nocase wide
        $str7 = "findTFTPServer" ascii nocase wide
        $str8 = "DHCPRequestRecon" ascii nocase wide
        $str9 = "DHCPDiscoverRecon" ascii nocase wide
        $str10 = "GoodieFile" ascii nocase wide
        $str11 = "InfoStore" ascii nocase wide
        $str12 = "execute" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
rule APT_HackTool_MSIL_PRAT_1
{
    meta:
        id = "2cyFwXp0HW7k8pF4Dda8kZ"
        fingerprint = "v1_sha256_d707f017b56b0a873f1edca085ad40fc70cb24e8c9844f377bc28871a941d0b4"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'prat' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "7d1219fb-a954-49a7-96c9-df9e6429a8c7" ascii nocase wide
        $typelibguid1 = "bc1157c2-aa6d-46f8-8d73-068fc08a6706" ascii nocase wide
        $typelibguid2 = "c602fae2-b831-41e2-b5f8-d4df6e3255df" ascii nocase wide
        $typelibguid3 = "dfaa0b7d-6184-4a9a-9eeb-c08622d15801" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_SHARPNATIVEZIPPER_1
{
    meta:
        id = "3xx1otfz2M0u4LirolPBMJ"
        fingerprint = "v1_sha256_fa54375b21abbb613e695f70a15233575fbe6e0536716544bb3b527f5e3ed8c6"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnativezipper' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3

    strings:
        $typelibguid0 = "de5536db-9a35-4e06-bc75-128713ea6d27" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win32_REDFLARE_1
{
    meta:
        id = "2Lx8XGjgQSWTy9yqadScfL"
        fingerprint = "v1_sha256_f9165aabe4bad215211cf98559099030ddb8a76175fbfcfee3c6f25d7614bdad"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "01d68343ac46db6065f888a094edfe4f"
        rev = 1

    strings:
        $alloc_n_load = { 6A 40 68 00 30 00 00 [0-20] 6A 00 [0-20] FF D0 [4-60] F3 A4 [30-100] 6B C0 28 8B 4D ?? 8B 4C 01 10 8B 55 ?? 6B D2 28 }
        $const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_Loader_MSIL_PGF_1
{
    meta:
        id = "3KJlsbs5OGMEoLWR5LsQbd"
        fingerprint = "v1_sha256_4174ed53336f3951d26282dc81b99b2044ac6350d4b4c0074194a9b4acecefee"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "base.cs"
        category = "TOOL"
        date_created = "2020-11-24"
        date_modified = "2020-11-24"
        md5 = "a495c6d11ff3f525915345fb762f8047"
        rev = 1

    strings:
        $sb1 = { 72 [4] 6F [2] 00 0A 26 [0-16] 0? 6F [2] 00 0A [1-3] 0? 28 [2] 00 0A [0-1] 0? 72 [4-5] 0? 28 [2] 00 0A [0-1] 0? 6F [2] 00 0A 13 ?? 1? 13 ?? 38 [8-16] 91 [3-6] 8E 6? 5D 91 61 D2 9C 11 ?? 1? 58 13 [3-5] 8E 6? 3F }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule CredTheft_Win_EXCAVATOR_2
{
    meta:
        id = "2dz5CY1r4FVi8UbV4phO5S"
        fingerprint = "v1_sha256_408e8862f0c470105648fdba00dc5531ffcd739fa544f89acb70f0fa1b105c03"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This rule looks for the binary signature of the routine that calls PssFreeSnapshot found in the Excavator-Reflector DLL."
        category = "TOOL"
        md5 = "6a9a114928554c26675884eeb40cc01b"
        rev = 3

    strings:
        $bytes1 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A0 01 00 00 48 8B 05 4C 4A 01 00 48 33 C4 48 89 85 90 00 00 00 BA 50 00 00 00 C7 05 CB 65 01 00 43 00 3A 00 66 89 15 EC 65 01 00 4C 8D 44 24 68 48 8D 15 D8 68 01 00 C7 05 B2 65 01 00 5C 00 57 00 33 C9 C7 05 AA 65 01 00 69 00 6E 00 C7 05 A4 65 01 00 64 00 6F 00 C7 05 9E 65 01 00 77 00 73 00 C7 05 98 65 01 00 5C 00 4D 00 C7 05 92 65 01 00 45 00 4D 00 C7 05 8C 65 01 00 4F 00 52 00 C7 05 86 65 01 00 59 00 2E 00 C7 05 80 65 01 00 44 00 4D 00 C7 05 72 68 01 00 53 00 65 00 C7 05 6C 68 01 00 44 00 65 00 C7 05 66 68 01 00 42 00 75 00 C7 05 60 68 01 00 47 00 50 00 C7 05 5A 68 01 00 72 00 69 00 C7 05 54 68 01 00 56 00 69 00 C7 05 4E 68 01 00 4C 00 45 00 C7 05 48 68 01 00 67 00 65 00 C7 05 12 67 01 00 6C 73 61 73 C7 05 0C 67 01 00 73 2E 65 78 C6 05 09 67 01 00 65 FF 15 63 B9 00 00 45 33 F6 85 C0 74 66 48 8B 44 24 68 48 89 44 24 74 C7 44 24 70 01 00 00 00 C7 44 24 7C 02 00 00 00 FF 15 A4 B9 00 00 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF 15 1A B9 00 00 85 C0 74 30 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF 15 EF B8 00 00 FF 15 11 B9 00 00 48 8B 4C 24 48 FF 15 16 B9 00 00 48 89 9C 24 B0 01 00 00 48 8D 0D BF 2E 01 00 48 89 B4 24 B8 01 00 00 4C 89 74 24 40 FF 15 1C B9 00 00 48 85 C0 0F 84 B0 00 00 00 48 8D 15 AC 2E 01 00 48 8B C8 FF 15 1B B9 00 00 48 8B D8 48 85 C0 0F 84 94 00 00 00 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 06 15 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 63 66 0F 1F 44 00 00 48 8B 4C 24 40 4C 8D 45 80 41 B9 04 01 00 00 33 D2 FF 15 89 B8 00 00 48 8D 15 F2 65 01 00 48 8D 4D 80 E8 49 0F 00 00 48 85 C0 75 38 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 A3 14 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 A3 33 C0 E9 F5 00 00 00 48 8B 5C 24 40 48 8B CB FF 15 5E B8 00 00 8B F0 48 85 DB 74 E4 85 C0 74 E0 4C 8D 4C 24 50 48 89 BC 24 C0 01 00 00 BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 12 B8 00 00 85 C0 0F 85 A0 00 00 00 48 8D 05 43 FD FF FF 4C 89 74 24 30 C7 44 24 28 80 00 00 00 48 8D 0D 3F 63 01 00 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 4C 89 74 24 60 FF 15 E4 B7 00 00 48 8B F8 48 83 F8 FF 74 59 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 00 00 00 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF 15 B1 B9 00 00 48 8B CB FF 15 78 B7 00 00 48 8B CF FF 15 6F B7 00 00 FF 15 B1 B7 00 00 48 8B 54 24 50 48 8B C8 FF 15 53 B7 00 00 33 C9 FF 15 63 B7 00 00 CC 48 8B CB FF 15 49 B7 00 00 48 8B BC 24 C0 01 00 00 33 C0 48 8B B4 24 B8 01 00 00 48 8B 9C 24 B0 01 00 00 48 8B 8D 90 00 00 00 48 33 CC E8 28 00 00 00 4C 8B B4 24 C8 01 00 00 48 81 C4 A0 01 00 00 5D C3 }
        $bytes2 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
        $bytes3 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
        $bytes4 = { 4C 89 74 24 ?? 55 48 8D AC 24 ?? ?? ?? ?? 48 81 EC A0 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? BA 50 00 00 00 C7 05 ?? ?? ?? ?? 43 00 3A 00 66 89 15 ?? ?? 01 00 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 5C 00 57 00 33 C9 C7 05 ?? ?? ?? ?? 69 00 6E 00 C7 05 ?? ?? ?? ?? 64 00 6F 00 C7 05 ?? ?? ?? ?? 77 00 73 00 C7 05 ?? ?? ?? ?? 5C 00 4D 00 C7 05 ?? ?? ?? ?? 45 00 4D 00 C7 05 ?? ?? ?? ?? 4F 00 52 00 C7 05 ?? ?? ?? ?? 59 00 2E 00 C7 05 ?? ?? ?? ?? 44 00 4D 00 C7 05 ?? ?? ?? ?? 53 00 65 00 C7 05 ?? ?? ?? ?? 44 00 65 00 C7 05 ?? ?? ?? ?? 42 00 75 00 C7 05 ?? ?? ?? ?? 47 00 50 00 C7 05 ?? ?? ?? ?? 72 00 69 00 C7 05 ?? ?? ?? ?? 56 00 69 00 C7 05 ?? ?? ?? ?? 4C 00 45 00 C7 05 ?? ?? ?? ?? 67 00 65 00 C7 05 ?? ?? ?? ?? 6C 73 61 73 C7 05 ?? ?? ?? ?? 73 2E 65 78 C6 05 ?? ?? ?? ?? 65 FF 15 ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 ?? 48 89 44 24 ?? C7 44 24 ?? 01 00 00 00 C7 44 24 ?? 02 00 00 00 FF 15 ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 ?? 41 8D 56 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 4C 8D 44 24 ?? 4C 89 74 24 ?? 45 33 C9 33 D2 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 B4 24 ?? ?? ?? ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 0F 1F 44 00 ?? 48 8B 4C 24 ?? 4C 8D 45 ?? 41 B9 04 01 00 00 33 D2 FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B CB FF 15 ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 ?? 48 89 BC 24 ?? ?? ?? ?? BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 4C 89 74 24 ?? C7 44 24 ?? 80 00 00 00 48 8D 0D ?? ?? ?? ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 01 00 00 00 BA 00 00 00 10 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 ?? 41 B9 02 00 00 00 4C 89 74 24 ?? 4C 8B C7 8B D6 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 54 24 ?? 48 8B C8 FF 15 ?? ?? ?? ?? 33 C9 FF 15 ?? ?? ?? ?? CC 48 8B CB FF 15 ?? ?? ?? ?? 48 8B BC 24 ?? ?? ?? ?? 33 C0 48 8B B4 24 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 ?? ?? ?? ?? 48 81 C4 A0 01 00 00 5D C3 }
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and any of ($bytes*)
}
rule Builder_MSIL_SharpGenerator_1
{
    meta:
        id = "4PMXTiiFbdY7Sl4EAmEMEg"
        fingerprint = "v1_sha256_6dc0780e54d33df733aadc8a89077232baa63bf1cbe47c5d164c57ce3185dd71"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGenerator' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "3f450977-d796-4016-bb78-c9e91c6a0f08" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Trojan_Win_REDFLARE_6
{
    meta:
        id = "2LsYj1NmCF1FDUqP3PwyjH"
        fingerprint = "v1_sha256_1e6f8320e0c0b601fc72fa4d9c61e46adfbcd84638c97da5988ca848e036312a"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "294b1e229c3b1efce29b162e7b3be0ab, 6902862bd81da402e7ac70856afbe6a2"
        rev = 2

    strings:
        $s1 = "RevertToSelf" fullword
        $s2 = "Unsuccessful" fullword
        $s3 = "Successful" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule HackTool_Win64_AndrewSpecial_1
{
    meta:
        id = "7AXmQZSYDuBgfZe1RyYYsS"
        fingerprint = "v1_sha256_96f06c46dfec795fcfd08c188853d0a3f781003ae118833719a175eb59049c0d"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "4456e52f6f8543c3ba76cb25ea3e9bd2"
        rev = 5

    strings:
        $dump = { 33 D2 B9 FF FF 1F 00 FF 15 [10-90] 00 00 00 00 [2-6] 80 00 00 00 [2-6] 02 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4-120] 00 00 00 00 [2-6] 00 00 00 00 [2-6] 00 00 00 00 41 B9 02 00 00 00 [6-15] E8 [4-20] FF 15 }
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x64_inline = { C6 44 24 ?? 4C C6 44 24 ?? 8B C6 44 24 ?? D1 C6 44 24 ?? B8 C6 44 24 ?? 3C C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 0F C6 44 24 ?? 05 C6 44 24 ?? C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and $dump and any of ($shellcode*)
}
rule Loader_MSIL_Generic_1
{
    meta:
        id = "1kdNcGz9Fo3EV1CRyswQD3"
        fingerprint = "v1_sha256_06cddd7e1c1c778348539cfd50f01d55f86689dec86c045d7ce7b9cd71690e07"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        md5 = "b8415b4056c10c15da5bba4826a44ffd"
        rev = 5

    strings:
        $MSIL = "_CorExeMain"
        $opc1 = { 00 72 [4] 0A 72 [4] 0B 06 28 [4] 0C 12 03 FE 15 [4] 12 04 FE 15 [4] 07 14 }
        $str1 = "DllImportAttribute"
        $str2 = "FromBase64String"
        $str3 = "ResumeThread"
        $str4 = "OpenThread"
        $str5 = "SuspendThread"
        $str6 = "QueueUserAPC"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of them
}
rule APT_Keylogger_Win32_REDFLARE_1
{
    meta:
        id = "12aR3yqrJDeRnjeBw8SbuF"
        fingerprint = "v1_sha256_aebbaa050bee3775ffac4214ea4ab58284384e7eb41e66ee4838b9359e72821e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "d7cfb9fbcf19ce881180f757aeec77dd"
        rev = 2

    strings:
        $create_window = { 6A 00 68 [4] 6A 00 6A 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 CF 00 68 [4] 68 [4] 6A 00 FF 15 }
        $keys_check = { 6A 14 [0-5] FF [1-5] 6A 10 [0-5] FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A0 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A1 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule Loader_MSIL_InMemoryCompilation_1
{
    meta:
        id = "7EQgwH23wK765QCycIbQLL"
        fingerprint = "v1_sha256_a964a186eb02a2792db01727a31ddaa2414fe9df83cda9b1c9db15d94603303a"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'In-MemoryCompilation' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "524d2687-0042-4f93-b695-5579f3865205" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_WMISharp_1
{
    meta:
        id = "7HXGavC4WqP95eVbXyz9ZD"
        fingerprint = "v1_sha256_d119d52c1410291d582696d5c4c1de3db9008db963c76a9e344959d869c3acc0"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMISharp' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "3a2421d9-c1aa-4fff-ad76-7fcb48ed4bff" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win_PGF_2
{
    meta:
        id = "6nxiR4JRCr0LHnWmglZEzZ"
        fingerprint = "v1_sha256_b8c024c6b4c3ce9915700b62da8a1f12440215b46f3a56078707f5257e575811"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "PE rich header matches PGF backdoor"
        category = "TOOL"
        md5 = "226b1ac427eb5a4dc2a00cc72c163214"
        md5_2 = "2398ed2d5b830d226af26dedaf30f64a"
        md5_3 = "24a7c99da9eef1c58f09cf09b9744d7b"
        md5_4 = "aeb0e1d0e71ce2a08db9b1e5fb98e0aa"
        rev = 4

    strings:
        $rich1 = { A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69 }
        $rich2 = { C1 CF 75 A4 85 AE 1B F7 85 AE 1B F7 85 AE 1B F7 8C D6 88 F7 83 AE 1B F7 0D C9 1A F6 87 AE 1B F7 0D C9 1E F6 8F AE 1B F7 0D C9 1F F6 8F AE 1B F7 0D C9 18 F6 84 AE 1B F7 DE C6 1A F6 86 AE 1B F7 85 AE 1A F7 BF AE 1B F7 84 C3 12 F6 81 AE 1B F7 84 C3 E4 F7 84 AE 1B F7 84 C3 19 F6 84 AE 1B F7 }
        $rich3 = { D6 60 82 B8 92 01 EC EB 92 01 EC EB 92 01 EC EB 9B 79 7F EB 94 01 EC EB 1A 66 ED EA 90 01 EC EB 1A 66 E9 EA 98 01 EC EB 1A 66 E8 EA 9A 01 EC EB 1A 66 EF EA 90 01 EC EB C9 69 ED EA 91 01 EC EB 92 01 ED EB AF 01 EC EB 93 6C E5 EA 96 01 EC EB 93 6C 13 EB 93 01 EC EB 93 6C EE EA 93 01 EC EB }
        $rich4 = { 41 36 64 33 05 57 0A 60 05 57 0A 60 05 57 0A 60 73 CA 71 60 01 57 0A 60 0C 2F 9F 60 04 57 0A 60 0C 2F 89 60 3D 57 0A 60 0C 2F 8E 60 0A 57 0A 60 05 57 0B 60 4A 57 0A 60 0C 2F 99 60 06 57 0A 60 73 CA 67 60 04 57 0A 60 0C 2F 98 60 04 57 0A 60 0C 2F 80 60 04 57 0A 60 22 91 74 60 04 57 0A 60 0C 2F 9B 60 04 57 0A 60 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and (($rich1 at 128) or ($rich2 at 128) or ($rich3 at 128) or ($rich4 at 128))
}
rule Trojan_Win_Generic_101
{
    meta:
        id = "19Rd0yFFfB0sVrCpi5nL84"
        fingerprint = "v1_sha256_e530183f3cab01560b1abc91e2111e5d9e5aadc1c8134027ac07d8917f9419a0"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "2e67c62bd0307c04af469ee8dcb220f2"
        rev = 3

    strings:
        $s0 = { 2A [1-16] 17 [1-16] 02 04 00 00 [1-16] FF 15 }
        $s1 = { 81 7? [1-3] 02 04 00 00 7? [1-3] 83 7? [1-3] 17 7? [1-3] 83 7? [1-3] 2A 7? }
        $s2 = { FF 15 [4-16] FF D? [1-16] 3D [1-24] 89 [1-8] E8 [4-16] 89 [1-8] F3 A4 [1-24] E8 }
        $si1 = "PeekMessageA" fullword
        $si2 = "PostThreadMessageA" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and @s0[1] < @s1[1] and @s1[1] < @s2[1] and all of them
}
rule Trojan_Macro_RESUMEPLEASE_1
{
    meta:
        id = "6Eyyrvr4bIzhcTve1mqN77"
        fingerprint = "v1_sha256_040457bc446e496431129ff4623ddda5d9c2ce339ba65a7fbe42114626f36c60"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "d5d3d23c8573d999f1c48d3e211b1066"
        rev = 1

    strings:
        $str00 = "For Binary As"
        $str01 = "Range.Text"
        $str02 = "Environ("
        $str03 = "CByte("
        $str04 = ".SpawnInstance_"
        $str05 = ".Create("
    condition:
        all of them
}
rule Loader_MSIL_CSharpSectionInjection_1
{
    meta:
        id = "fAfMNG3q1hTj8Hs9llBoE"
        fingerprint = "v1_sha256_011cf4dffe6ef90a79cdfabb0e297152c00b0404b1801f56fd7e703ab90b1692"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'C_Sharp_SectionInjection' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "d77135da-0496-4b5c-9afe-e1590a4c136a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_SHARPWEBCRAWLER_1
{
    meta:
        id = "489D03eBCgQzwFzMB9Yl1U"
        fingerprint = "v1_sha256_8df328663a813ca0a6864ae0503cbc1b03cfdf839215b9b4f2bb7962adf09bf8"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpwebcrawler' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "cf27abf4-ef35-46cd-8d0c-756630c686f1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Trojan_Win64_Generic_22
{
    meta:
        id = "51JmSsDUew9gMzPwg62EXf"
        fingerprint = "v1_sha256_52fbe5c0ee7c05df5fcd62c26caaa5498e32352da9c5940e522aa31d6c808028"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        rev = 2

    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { C7 44 24 20 40 00 00 00 33 D2 41 B9 00 30 00 00 41 B8 [4] 48 8B CB FF 15 [4] 48 8B F0 48 85 C0 74 ?? 4C 89 74 24 20 41 B9 [4] 4C 8D 05 [4] 48 8B D6 48 8B CB FF 15 [4] 85 C0 75 [5-10] 4C 8D 0C 3E 48 8D 44 24 ?? 48 89 44 24 30 44 89 74 24 28 4C 89 74 24 20 33 D2 41 B8 [4] 48 8B CB FF 15 }
        $process = { 89 74 24 30 ?? 8D 4C 24 [2] 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 [4] 85 C0 0F 84 [4] 48 8B [2-3] 48 8D 45 ?? 48 89 44 24 50 4C 8D 05 [4] 48 8D 45 ?? 48 89 7D 08 48 89 44 24 48 45 33 C9 ?? 89 74 24 40 33 D2 ?? 89 74 24 38 C7 44 24 30 04 00 08 00 [0-1] 89 74 24 28 ?? 89 74 24 20 FF 15 }
        $token = { FF 15 [4] 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 0F 84 [4] 48 8B 4C 24 ?? 48 8D [2-3] 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 [4] 85 C0 0F 84 [4] 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 01 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}
rule Loader_Win_Generic_19
{
    meta:
        id = "3NYt8CVLE05Xnsas6zRv00"
        fingerprint = "v1_sha256_6db9696663c19857c1f89339b8cc9b0565e877f34e8d8cf77b89ef22b3f41683"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "3fb9341fb11eca439b50121c6f7c59c7"
        rev = 1

    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Builder_PY_REDFLARE_1
{
    meta:
        id = "4SPW0Re31mqHtHUtNoz3d5"
        fingerprint = "v1_sha256_1948cadb7242eb69bffbc222802ce9c1af38d7a846da09b6343b1449fe054e42"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "d0a830403e56ebaa4bfbe87dbfdee44f"
        rev = 1

    strings:
        $1 = "LOAD_OFFSET_32 = 0x612"
        $2 = "LOAD_OFFSET_64 = 0x611"
        $3 = "class RC4:"
        $4 = "struct.pack('<Q' if is64b else '<L'"
        $5 = "stagerConfig['comms']['config']"
        $6 = "_x86.dll"
        $7 = "_x64.dll"
    condition:
        all of them and @1[1] < @2[1] and @2[1] < @3[1] and @3[1] < @4[1] and @4[1] < @5[1]
}
rule HackTool_PY_ImpacketObfuscation_2
{
    meta:
        id = "3oD40sz3DuJx9hIE7wLXXN"
        fingerprint = "v1_sha256_ccbbe507798f16c7acf0780770fdb81b2e7dc333ab8bc51e6216816276c3f14b"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "wmiexec"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "f3dd8aa567a01098a8a610529d892485"
        rev = 2

    strings:
        $s1 = "import random"
        $s2 = "class WMIEXEC" nocase
        $s3 = "class RemoteShell" nocase
        $s4 = /=[\x09\x20]{0,32}str\(int\(time\.time\(\)\)[\x09\x20]{0,32}-[\x09\x20]{0,32}random\.randint\(\d{1,10}[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,10}\)\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}str\(uuid\.uuid4\(\)\)\.split\([\x22\x27]\-[\x22\x27]\)\[0\]/
        $s5 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]cmd.exe[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
    condition:
        all of them
}
rule APT_Loader_MSIL_PGF_2
{
    meta:
        id = "40K72Vq6eCjAJYgeFiTaAM"
        fingerprint = "v1_sha256_b962ea30c063009c0383e25edda3a65202bea4496d0d6228549dcea82bba0d03"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "base.js, ./lib/payload/techniques/jscriptdotnet/jscriptdotnet_payload.py"
        category = "TOOL"
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "7c2a06ceb29cdb25f24c06f2a8892fba"
        rev = 1

    strings:
        $sb1 = { 2? 00 10 00 00 0A 1? 40 0? 72 [4] 0? 0? 28 [2] 00 0A 0? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 0? 74 [2] 00 01 28 [2] 00 0A 6? 0? 0? 28 [2] 00 06 D0 [2] 00 01 28 [2] 00 0A 1? 28 [2] 00 0A 79 [2] 00 01 71 [2] 00 01 13 ?? 0? 1? 11 ?? 0? 74 [2] 00 01 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 13 ?? 1? 13 ?? 7E [2] 00 0A 13 ?? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 1? 11 ?? 11 ?? 1? 11 ?? 28 [2] 00 06 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "\x00ScriptObjectStackTop\x00"
        $ss3 = "\x00Microsoft.JScript\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_SHARPSQLCLIENT_1
{
    meta:
        id = "zrcHpRTAh5AYhhyGDH0uw"
        fingerprint = "v1_sha256_bc79f80582f4fadecf54d926abdcf61694224654ba5075203f0d1123cf11afc1"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsqlclient' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "13ed03cd-7430-410d-a069-cf377165fbfd" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Methodology_OLE_CHARENCODING_2
{
    meta:
        id = "2XddmYOTM1QzKrghCtmL6q"
        fingerprint = "v1_sha256_20843295531dfd88934fe0902a5101c5c0828e82df3289d7f263f16df9c92324"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "Looking for suspicious char encoding"
        category = "TOOL"
        md5 = "41b70737fa8dda75d5e95c82699c2e9b"
        rev = 4

    strings:
        $echo1 = "101;99;104;111;32;111;102;102;" ascii wide
        $echo2 = "101:99:104:111:32:111:102:102:" ascii wide
        $echo3 = "101x99x104x111x32x111x102x102x" ascii wide
        $pe1 = "77;90;144;" ascii wide
        $pe2 = "77:90:144:" ascii wide
        $pe3 = "77x90x144x" ascii wide
        $pk1 = "80;75;3;4;" ascii wide
        $pk2 = "80:75:3:4:" ascii wide
        $pk3 = "80x75x3x4x" ascii wide
    condition:
        (uint32(0) == 0xe011cfd0) and filesize < 10MB and any of them
}
rule HackTool_MSIL_SharpHound_3
{
    meta:
        id = "2V3sYP93JGPQ44ScANiv5o"
        fingerprint = "v1_sha256_baeea6cae42c755ee389378229b2b206c82f60f75a5ce5f9cfa06871fc9507d1"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SharpHound3 project."
        category = "TOOL"
        md5 = "eeedc09570324767a3de8205f66a5295"
        rev = 4

    strings:
        $typelibguid1 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule CredTheft_MSIL_TitoSpecial_2
{
    meta:
        id = "j5Sw9ieW923KF1MFBsoCL"
        fingerprint = "v1_sha256_2f621f8de2a4679e6cbce7f41859eaa3095ca54090c8bfccd3b767590ac91f2c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the TitoSpecial project. There are 2 GUIDs in this rule as the x86 and x64 versions of this tool use a different ProjectGuid."
        category = "TOOL"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 4

    strings:
        $typelibguid1 = "C6D94B4C-B063-4DEB-A83A-397BA08515D3" ascii nocase wide
        $typelibguid2 = "3b5320cf-74c1-494e-b2c8-a94a24380e60" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ($typelibguid1 or $typelibguid2)
}
rule CredTheft_MSIL_WCMDump_1
{
    meta:
        id = "1ahQtvO0mHE3pM5sXtTnVT"
        fingerprint = "v1_sha256_9fbf53e551342695b306b10f30a3fe32dff359bd70e84e1fa1f190772f5dcbe3"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WCMDump' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "21e322f2-4586-4aeb-b1ed-d240e2a79e19" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Builder_Win64_MATRYOSHKA_1
{
    meta:
        id = "4Tgv4E4BMk1DP1Ue2eSpH9"
        fingerprint = "v1_sha256_b370d7dea44bccc92fc8dbd4ea0ee9bec523820108bf8bc67acb17ebf9835f74"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "matryoshka_pe_to_shellcode.rs"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "8d949c34def898f0f32544e43117c057"
        rev = 1

    strings:
        $sb1 = { 4D 5A 45 52 [0-32] E8 [0-32] 00 00 00 00 [0-32] 5B 48 83 EB 09 53 48 81 [0-32] C3 [0-32] FF D3 [0-32] C3 }
        $ss1 = "\x00Stub Size: "
        $ss2 = "\x00Executable Size: "
        $ss3 = "\x00[+] Writing out to file"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule Trojan_Win64_Generic_23
{
    meta:
        id = "4DXLSTk1ulRZzVRmTRscxm"
        fingerprint = "v1_sha256_4c1860801b26abbab8c4aea730bf69f388c902083b9945e11e6782af3ab22789"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "b66347ef110e60b064474ae746701d4a"
        rev = 1

    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { 8B 85 [4] C7 44 24 20 40 00 00 00 41 B9 00 30 00 00 44 8B C0 33 D2 48 8B 8D [4] FF 15 [4] 48 89 45 ?? 48 83 7D ?? 00 75 ?? 48 8B 45 ?? E9 [4] 8B 85 [4] 48 C7 44 24 20 00 00 00 00 44 8B C8 4C 8B 85 [4] 48 8B 55 ?? 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? 48 8B 45 ?? EB ?? 8B 85 [4] 48 8B 4D ?? 48 03 C8 48 8B C1 48 89 45 48 48 8D 85 [4] 48 89 44 24 30 C7 44 24 28 00 00 00 00 48 8B 85 [4] 48 89 44 24 20 4C 8B 4D ?? 41 B8 00 00 10 00 33 D2 48 8B 8D [4] FF 15 }
        $process = { 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 08 00 00 00 4C 8D 8D [4] 41 B8 00 00 02 00 33 D2 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? E9 [4] 48 8B 85 [4] 48 89 85 [4] 48 8D 85 [4] 48 89 44 24 50 48 8D 85 [4] 48 89 44 24 48 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 C7 44 24 30 04 00 08 00 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 05 [4] 33 D2 48 8B [2-5] FF 15 }
        $token = { FF 15 [4] 4C 8D 45 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 75 ?? E9 [4] 48 8D [2-5] 48 89 44 24 28 C7 44 24 20 02 00 00 00 41 B9 02 00 00 00 45 33 C0 BA 0B 00 00 00 48 8B 4D ?? FF 15 [4] 85 C0 75 ?? E9 [4] 4C 8D 8D [4] 45 33 C0 BA 01 00 00 00 33 C9 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}
rule HackTool_MSIL_KeePersist_1
{
    meta:
        id = "uFgFYzFSogy273ftVA0ax"
        fingerprint = "v1_sha256_eae67c77a64ca07f9ef59a356bb2c3f3131f14e7f17c898ef8857a21090ace0e"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeePersist' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "1df47db2-7bb8-47c2-9d85-5f8d3f04a884" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Tool_MSIL_CSharpUtils_1
{
    meta:
        id = "5pT8UwZR7Mt4Xi5Dfmwy2W"
        fingerprint = "v1_sha256_11dfd44fb4ee1e610c2e4a941b3a1e88eafc30a2a2237529150e73bceb2a1324"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CSharpUtils' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "2130bcd9-7dd8-4565-8414-323ec533448d" ascii nocase wide
        $typelibguid1 = "319228f0-2c55-4ce1-ae87-9e21d7db1e40" ascii nocase wide
        $typelibguid2 = "4471fef9-84f5-4ddd-bc0c-31f2f3e0db9e" ascii nocase wide
        $typelibguid3 = "5c3bf9db-1167-4ef7-b04c-1d90a094f5c3" ascii nocase wide
        $typelibguid4 = "ea383a0f-81d5-4fa8-8c57-a950da17e031" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Trojan_MSIL_GORAT_Module_PowerShell_1
{
    meta:
        id = "6gDfOhq8wZdquU14ISVSzR"
        fingerprint = "v1_sha256_e596bc0316a4ef85f04c2683ebc7c94bf9b831843232c33e62c84991e4caeb97"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Module - PowerShell' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1

    strings:
        $typelibguid0 = "38d89034-2dd9-4367-8a6e-5409827a243a" ascii nocase wide
        $typelibguid1 = "845ee9dc-97c9-4c48-834e-dc31ee007c25" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_PuppyHound_1
{
    meta:
        id = "21YPxiTcdFgyv3qM554ugc"
        fingerprint = "v1_sha256_39073bbfef15ecd28c1772e5d01e54c3d5774ecb4c90f0076bda5dc400abacba"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "This is a modification of an existing FireEye detection for SharpHound. However, it looks for the string 'PuppyHound' instead of 'SharpHound' as this is all that was needed to detect the PuppyHound variant of SharpHound."
        category = "TOOL"
        md5 = "eeedc09570324767a3de8205f66a5295"
        rev = 6

    strings:
        $1 = "PuppyHound"
        $2 = "UserDomainKey"
        $3 = "LdapBuilder"
        $init = { 28 [2] 00 0A 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 28 [2] 00 0A 0B 1F 2D }
        $msil = /\x00_Cor(Exe|Dll)Main\x00/
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Builder_PY_MATRYOSHKA_1
{
    meta:
        id = "6WPYVjBDBehXCVyviBq3Xz"
        fingerprint = "v1_sha256_71b26f4b319429ac356b55d22bccd1da85894d61f8c96452422de78d2d893420"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "25a97f6dba87ef9906a62c1a305ee1dd"
        rev = 1

    strings:
        $s1 = ".pop(0)])"
        $s2 = "[1].replace('unsigned char buf[] = \"'"
        $s3 = "binascii.hexlify(f.read()).decode("
        $s4 = "os.system(\"cargo build {0} --bin {1}\".format("
        $s5 = "shutil.which('rustc')"
        $s6 = "~/.cargo/bin"
        $s7 = /[\x22\x27]\\\\x[\x22\x27]\.join\(\[\w{1,64}\[\w{1,64}:\w{1,64}[\x09\x20]{0,32}\+[\x09\x20]{0,32}2\]/
    condition:
        all of them
}
rule Loader_MSIL_RuralBishop_3
{
    meta:
        id = "r0KfjaiMo1uFuM6vVGH10"
        fingerprint = "v1_sha256_a4c55dede432c249e36e96ca09555448b0343969d389bfdb4bd459fe34e05ea1"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public RuralBishop project."
        category = "TOOL"
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        rev = 3

    strings:
        $typelibguid1 = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_HackTool_MSIL_NOAMCI_1
{
    meta:
        id = "cPCMzmsD3PKDWdLIEhyOG"
        fingerprint = "v1_sha256_6278cfb4e9af20bbe943f4b99227c7fba276315a9f0059575b3ed4ef96a848c4"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'noamci' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 4

    strings:
        $typelibguid0 = "7bcccf21-7ecd-4fd4-8f77-06d461fd4d51" ascii nocase wide
        $typelibguid1 = "ef86214e-54de-41c3-b27f-efc61d0accc3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_PXELOOT_1
{
    meta:
        id = "3K5R0LMo4VYsTpmNAzZ88r"
        fingerprint = "v1_sha256_c9892adcb9ff5471235e45988f6662d3b8f984fdafca7024a5781eed50f6c0b3"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the PXE And Loot project."
        category = "TOOL"
        md5 = "82e33011ac34adfcced6cddc8ea56a81"
        rev = 7

    strings:
        $typelibguid1 = "78B2197B-2E56-425A-9585-56EDC2C797D6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_HackTool_MSIL_ADPassHunt_2
{
    meta:
        id = "6O0GWr3P4oFeUOA2GsPJUy"
        fingerprint = "v1_sha256_e2dc7db1860eef04a569f007c32abd507dd588d1392613efbb31f42ca66ff735"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 1

    strings:
        $s1 = "LDAP://" wide
        $s2 = "[GPP] Searching for passwords now..." wide
        $s3 = "Searching Group Policy Preferences (Get-GPPPasswords + Get-GPPAutologons)!" wide
        $s4 = "possibilities so far)..." wide
        $s5 = "\\groups.xml" wide
        $s6 = "Found interesting file:" wide
        $s7 = "\x00GetDirectories\x00"
        $s8 = "\x00DirectoryInfo\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_ADPassHunt_1
{
    meta:
        id = "7XwiKeKaKw0IIgow6pUct7"
        fingerprint = "v1_sha256_63135c81c1a6b967cb26cced628afc0e7ef485923e6a7fd70a4d4672118d6a8c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 2

    strings:
        $sb1 = { 73 [2] 00 0A 0A 02 6F [2] 00 0A 0B 38 [4] 12 ?? 28 [2] 00 0A 0? 73 [2] 00 0A 0? 0? 0? 6F [2] 00 0A 1? 13 ?? 72 [4] 13 ?? 0? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 1? 3B [4] 11 ?? 72 [4] 28 [2] 00 0A 13 ?? 0? 72 [4] 6F [2] 00 0A 6F [2] 00 0A 13 ?? 38 [4] 11 ?? 6F [2] 00 0A 74 [2] 00 01 13 ?? 11 ?? 72 [4] 6F [2] 00 0A 2C ?? 11 ?? 72 [4] 11 ?? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 6F [2] 00 0A 72 [4] 28 [2] 00 0A }
        $sb2 = { 02 1? 8D [2] 00 01 [0-32] 1? 1F 2E 9D 6F [2] 00 0A 72 [4] 0A 0B 1? 0? 2B 2E 0? 0? 9A 0? 0? 72 [4] 6F [2] 00 0A 2D ?? 06 72 [4] 28 [2] 00 0A 0A 06 72 [4] 0? 28 [2] 00 0A 0A 0? 1? 58 0? 0? 0? 8E 69 32 CC 06 2A }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_SHARPSACK_1
{
    meta:
        id = "137IKEBCWxOQqRqgIq2xVE"
        fingerprint = "v1_sha256_ecc3250e65e34595b4b827add3eb3062edad6a3373930048bfd6225d4a229e93"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsack' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "1946808a-1a01-40c5-947b-8b4c3377f742" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win64_PGF_5
{
    meta:
        id = "wzYcDSisghrdSxM74ZCYq"
        fingerprint = "v1_sha256_16495ad1e5ce4d4a79f4067f3d687911a1a0a3bfe4c6409ff9de4d111b1ddca6"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "PGF payload, generated rule based on symfunc/8167a6d94baca72bac554299d7c7f83c"
        category = "TOOL"
        md5 = "150224a0ccabce79f963795bf29ec75b"
        rev = 3

    strings:
        $cond1 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 13 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 66 23 00 00 48 8B 4C 24 40 FF 15 EB F9 FF FF B8 01 00 00 00 48 83 C4 38 C3 }
        $cond2 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 A3 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 F6 20 00 00 48 8B 4C 24 40 FF 15 7B FA FF FF B8 01 00 00 00 48 83 C4 38 C3 }
        $cond3 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? 8B 44 24 48 89 44 24 20 83 7C 24 2? ?1 74 ?? EB ?? 48 8B 44 24 40 48 ?? ?? ?? ?? ?? ?? 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? 48 83 C4 38 C3 }
        $cond4 = { 4C 89 44 24 ?? 89 54 24 ?? 48 89 4C 24 ?? 48 83 EC 38 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 83 7C 24 ?? 01 74 ?? EB ?? 48 8B 44 24 ?? 48 89 05 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 48 83 C4 38 C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and any of them
}
rule APT_Trojan_Win_REDFLARE_2
{
    meta:
        id = "58E7MtTmErKDKbfTONS45S"
        fingerprint = "v1_sha256_1f2e1f644b1932486444dfda30b7dad7f50121f59fa493eb8a1a0528ae46db26"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1,05b99d438dac63a5a993cea37c036673"
        rev = 2

    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "Cookie: SID1=%s" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_DTRIM_1
{
    meta:
        id = "5uzf9sulykbsV5i5PVjkCJ"
        fingerprint = "v1_sha256_357c1f76631ec9ee342995cd12369fd9ff18c541bffe6f5464b1e8db45057196"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'dtrim' project, which is a modified version of SharpSploit."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "7760248f-9247-4206-be42-a6952aa46da2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SharPivot_2
{
    meta:
        id = "5bWyBXkvDwjsNxeznXJSQs"
        fingerprint = "v1_sha256_14e4a29a32e8441a6f7f322e09cd9bb9822ae47eaa1fdf8e09c90998b03658f5"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3

    strings:
        $s1 = "costura"
        $s2 = "cmd_schtask" wide
        $s3 = "cmd_wmi" wide
        $s4 = "cmd_rpc" wide
        $s5 = "GoogleUpdateTaskMachineUA" wide
        $s6 = "servicehijack" wide
        $s7 = "poisonhandler" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_REVOLVER_1
{
    meta:
        id = "wLQzxwxC40BBEhcevWXqP"
        fingerprint = "v1_sha256_8df8a56ed55b7857adb95daa643d544a49eb5f1952b4ad3ef757c34dad2ce317"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'revolver' project."
        category = "TOOL"
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 2

    strings:
        $typelibguid0 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide
        $typelibguid1 = "b214d962-7595-440b-abef-f83ecdb999d2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Keylogger_Win64_REDFLARE_1
{
    meta:
        id = "2mf38K2DNvo6Ek2NSSCNJW"
        fingerprint = "v1_sha256_26fe577ba637c484d9a8ccc2173b5892a76328a90a39a2bebbae6bd2a6329485"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "fbefb4074f1672a3c29c1a47595ea261"
        rev = 1

    strings:
        $create_window = { 41 B9 00 00 CF 00 [4-40] 33 C9 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 FF 15 }
        $keys_check = { B9 14 00 00 00 FF 15 [4-8] B9 10 00 00 00 FF 15 [4] BE 00 80 FF FF 66 85 C6 75 ?? B9 A0 00 00 00 FF 15 [4] 66 85 C6 75 ?? B9 A1 00 00 00 FF 15 [4] 66 85 C6 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_HackTool_Win64_EXCAVATOR_1
{
    meta:
        id = "YxQfD03rI5CjjTPtJEJlD"
        fingerprint = "v1_sha256_aa06628ddef0f95c4217b97a3476a0ee12e00d04c4827a512730598f3c80f1f6"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"
        date_created = "2020-11-30"
        date_modified = "2020-11-30"
        md5 = "6a9a114928554c26675884eeb40cc01b"
        rev = 3

    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { BA FD 03 00 AC [0-8] 41 B8 1F 00 10 00 48 8B ?? FF 15 [4] 85 C0 0F 85 [2] 00 00 [0-2] 48 8D 05 [5] 89 ?? 24 30 ( C7 44 24 28 80 00 00 00 48 8D 0D ?? ?? ?? ?? | 48 8D 0D ?? ?? ?? ?? C7 44 24 28 80 00 00 00 ) 45 33 C9 [0-5] 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 [0-10] FF 15 [4] 48 8B ?? 48 83 F8 FF ( 74 | 0F 84 ) [1-4] 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 30 ( 41 B9 02 00 00 00 | 44 8D 4D 02 ) ?? 89 ?? 24 28 4C 8B ?? 8B [2] 89 ?? 24 20 FF 15 [4] 48 8B ?? FF 15 [4] 48 8B ?? FF 15 [4] FF 15 [4] 48 8B 54 24 ?? 48 8B C8 FF 15 }
        $lsass = { 6C 73 61 73 [6] 73 2E 65 78 [6] 65 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}
rule APT_Loader_Win64_MATRYOSHKA_2
{
    meta:
        id = "73ZogjJV26qwqrSHPCaKx2"
        fingerprint = "v1_sha256_daa6f6d526bf959c268b2c5a4cae33307cfec5e9ca51283131bbfa66a582b505"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "matryoshka.rs"
        category = "TOOL"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "7f8102b789303b7861a03290c79feba0"
        rev = 1

    strings:
        $sb1 = { 4D [2] 00 49 [2] 08 B? 02 00 00 00 31 ?? E8 [4] 48 89 ?? 48 89 ?? 4C 89 ?? 49 89 ?? E8 [4] 4C 89 ?? 48 89 ?? E8 [4] 83 [2] 01 0F 84 [4] 48 89 ?? 48 8B [2] 48 8B [2] 48 89 [5] 48 89 [5] 48 89 [5] 41 B? [4] 4C 89 ?? 31 ?? E8 [4] C7 45 [5] 48 89 ?? 4C 89 ?? E8 [4] 85 C0 }
        $sb2 = { 4C [2] 0F 83 [4] 41 0F [3] 01 41 32 [2] 00 48 8B [5] 48 3B [5] 75 ?? 41 B? 01 00 00 00 4C 89 ?? E8 [4] E9 }
        $si1 = "CreateToolhelp32Snapshot" fullword
        $si2 = "Process32Next" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Backdoor_PS1_BASICPIPESHELL_1
{
    meta:
        id = "6ox17QcM1lkx5sNAoEvaQj"
        fingerprint = "v1_sha256_7a9f0002055ffe826562cab3d02d8babd14c5fcd6d0b528a2988e2649034279d"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"

    strings:
        $s1 = "function Invoke-Client()" ascii nocase wide
        $s2 = "function Invoke-Server" ascii nocase wide
        $s3 = "Read-Host 'Enter Command:'" ascii nocase wide
        $s4 = "new-object System.IO.Pipes.NamedPipeClientStream(" ascii nocase wide
        $s5 = "new-object System.IO.Pipes.NamedPipeServerStream(" ascii nocase wide
        $s6 = " = iex $" ascii nocase wide
    condition:
        all of them
}
rule APT_Loader_MSIL_LUALOADER_1
{
    meta:
        id = "4UQubo5V1OL3k0AtTEcRD9"
        fingerprint = "v1_sha256_2d73d434ac39ebde990aca817a54208cd04bfbce33f1bcadcf48a50d9389658c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"

    strings:
        $sb1 = { 1? 72 [4] 14 D0 [2] 00 02 28 [2] 00 0A 1? 8D [2] 00 01 13 ?? 11 ?? 1? 1? 14 28 [2] 00 0A A2 11 ?? 1? 1? 14 28 [2] 00 0A A2 11 ?? 28 [2] 00 0A 28 [2] 00 0A 80 [2] 00 04 7E [2] 00 04 7B [2] 00 0A 7E [2] 00 04 11 ?? 11 ?? 6F [2] 00 0A 6F [2] 00 0A }
        $ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
        $ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
        $ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
        $ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
        $ss5 = "1F 8B 08 00 00 00 00 00" wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_MSIL_LUALOADER_2
{
    meta:
        id = "6H0z2d4m3FV7hNzZHHH4bI"
        fingerprint = "v1_sha256_700927768669eda6976071306e991bfaae136279f4265980521597c699fbed88"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"

    strings:
        $ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
        $ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
        $ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
        $ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
        $ss5 = "1F 8B 08 00 00 00 00 00" wide
        $ss6 = "\x00LoadLibrary\x00"
        $ss7 = "\x00GetProcAddress\x00"
        $ss8 = "\x00VirtualProtect\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule FE_APT_Loader_MSIL_REVOLVER_1
{
    meta:
        id = "3rR019R6ngMCgnmbhIsyKl"
        fingerprint = "v1_sha256_1231f4c961dec122ebcb142052c2c7c03acf9b556cdb71a3efabde6bcf50a939"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"

    strings:
        $inject = { 28 [2] 00 06 0? 0? 7B [2] 00 04 7E [2] 00 0A 28 [2] 00 0A [2-40] 7E [2] 00 0A 0? 20 00 10 00 00 28 [2] 00 0A 0? 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? ?? 20 00 30 00 00 1F 40 28 [2] 00 06 [2-40] 28 [2] 00 0A 1? 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 1? ?? FE 15 [2] 00 02 1? ?? 72 [2] 00 70 28 [2] 00 06 1? ?? FE 15 [2] 00 02 1? ?? 1? ?? 1? 28 [2] 00 06 2? 7E [2] 00 0A 1? ?? 0? 7B [2] 00 04 1? ?? 1? 1? ?? 28 [2] 00 06 2? ?? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-10] 7E [2] 00 0A 1? ?? 1? ?? 20 [2] 1F 00 7E [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? 1? 20 [2] 00 00 20 [2] 00 00 7E [2] 00 0A 28 [2] 00 06 2? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-40] 1? ?? 0? 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 2? ?? 2? 1? 1? ?? 1? ?? 1? ?? 28 [2] 00 06 }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_MSIL_DUEDLLIGENCE_1
{
    meta:
        id = "DRjN985JdGSITYkhA2UfC"
        fingerprint = "v1_sha256_56237d686b954950849adeedc87d5f9fbff2335a0ff033ba8571b3e3b93f587c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"

    strings:
        $create_thread_injected = { 7E [2] 00 0A 0A 16 0B 16 8D [2] 00 01 0C 28 [2] 00 06 2? ?? 2A 28 [2] 00 0A 1E 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 7E [2] 00 0A 08 8E 69 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 0D 09 7E [2] 00 0A 28 [2] 00 0A }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
        $suspended_process = { 12 ?? FE 15 [2] 00 02 1? ?? FE 15 [2] 00 02 02 14 7E [2] 00 0A 7E [2] 00 0A 16 20 [2] 00 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_MSIL_DUEDLLIGENCE_2
{
    meta:
        id = "5b4nnSav6RSefOFHtRiN3l"
        fingerprint = "v1_sha256_5a2e0559e3b47c1957a42929fbbeba7a53c21619125381b01dcd8453b6ec4802"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"

    strings:
        $1 = "DueDLLigence" fullword
        $2 = "CPlApplet" fullword
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_MSIL_DUEDLLIGENCE_3
{
    meta:
        id = "6ZFno2xcTpf5fhGBkiZQJs"
        fingerprint = "v1_sha256_41cc6a4c7765b1e5e88d12660b69e434c83938ca974b9ccf6545b4dd5dd78378"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MANDIANT"
        author = "FireEye"
        description = "NA"
        category = "TOOL"

    strings:
        $create_thread_injected = { 7E [2] 00 0A 0A 16 0B 16 8D [2] 00 01 0C 28 [2] 00 06 2? ?? 2A 28 [2] 00 0A 1E 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 7E [2] 00 0A 08 8E 69 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 0D 09 7E [2] 00 0A 28 [2] 00 0A }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
        $rc4 = { 20 00 01 00 00 8D [2] 00 01 1? ?? 20 00 01 00 00 8D [2] 00 01 1? ?? 03 8E 69 8D [2] 00 01 1? ?? 16 0B 2B ?? 1? ?? 07 02 07 02 8E 69 5D 91 9E 1? ?? 07 07 9E 07 17 58 0B 07 20 00 01 00 00 32 }
        $suspended_process = { 12 ?? FE 15 [2] 00 02 1? ?? FE 15 [2] 00 02 02 14 7E [2] 00 0A 7E [2] 00 0A 16 20 [2] 00 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
