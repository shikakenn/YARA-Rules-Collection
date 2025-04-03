// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Keylogger_Win64_REDFLARE_1
{
    meta:
        id = "4uoNzP6KGUSCcMfirEu144"
        fingerprint = "v1_sha256_26fe577ba637c484d9a8ccc2173b5892a76328a90a39a2bebbae6bd2a6329485"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"
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
