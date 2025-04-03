// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_1
{
    meta:
        id = "1yZWcrFqYcXsqSfJsREEQJ"
        fingerprint = "v1_sha256_08ea2151418f7f75a8b138146c393a5ea85647320cc8e9fe1930d75871ab94bb"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"
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
