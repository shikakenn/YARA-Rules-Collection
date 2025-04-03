// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Builder_PY_MATRYOSHKA_1
{
    meta:
        id = "5XpwQX0ZcfAN0DhvNXqt56"
        fingerprint = "v1_sha256_71b26f4b319429ac356b55d22bccd1da85894d61f8c96452422de78d2d893420"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"
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
