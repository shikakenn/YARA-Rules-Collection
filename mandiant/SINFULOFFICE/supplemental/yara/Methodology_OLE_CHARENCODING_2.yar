// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Methodology_OLE_CHARENCODING_2
{
    meta:
        id = "2mMz71fQDSGn0MHwockgcz"
        fingerprint = "v1_sha256_20843295531dfd88934fe0902a5101c5c0828e82df3289d7f263f16df9c92324"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "Looking for suspicious char encoding"
        category = "INFO"
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
