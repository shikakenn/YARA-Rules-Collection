// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Dropper_Win_MATRYOSHKA_1
{
    meta:
        id = "4WtiototzyodeauN3vUQgV"
        fingerprint = "v1_sha256_a7bf7599ec9b4b1d09a8c90b70ae565a9396fb31d449da3c1492d6fa336d9c5e"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "matryoshka_dropper.rs"
        category = "INFO"
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
