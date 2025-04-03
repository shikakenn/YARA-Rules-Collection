// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_PY_ImpacketObfuscation_2
{
    meta:
        id = "56IQbXcOVgjNUZY13K5YPq"
        fingerprint = "v1_sha256_ccbbe507798f16c7acf0780770fdb81b2e7dc333ab8bc51e6216816276c3f14b"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "wmiexec"
        category = "INFO"
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
