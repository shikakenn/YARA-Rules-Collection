// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Hunting_B64Engine_DotNetToJScript_Dos
{
    meta:
        id = "19kPVURtwOI2MF6idJ7dV7"
        fingerprint = "v1_sha256_e2afb43af469f8ae02f6fd21db6dbd45c997fb003e3aeeaa0d4ff3e85c64159a"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "This file may enclude a Base64 encoded .NET executable. This technique is used by the project DotNetToJScript which is used by many malware families including GadgetToJScript."
        category = "INFO"
        md5 = "7af24305a409a2b8f83ece27bb0f7900"
        rev = 1

    strings:
        $b64_mz = "AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEU"
    condition:
        $b64_mz
}
