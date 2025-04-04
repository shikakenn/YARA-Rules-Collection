// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Builder_Win64_MATRYOSHKA_1
{
    meta:
        id = "YR0SjPCxKg7r0peHqmHoo"
        fingerprint = "v1_sha256_b370d7dea44bccc92fc8dbd4ea0ee9bec523820108bf8bc67acb17ebf9835f74"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "matryoshka_pe_to_shellcode.rs"
        category = "INFO"
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
