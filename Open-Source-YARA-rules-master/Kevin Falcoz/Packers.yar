import "pe"

rule upx_0_80_to_1_24 : Packer
{
    meta:
        id = "4PyUrHE2RdS7bs7RI0xje4"
        fingerprint = "v1_sha256_65219fb8672462ff0e907024df191d38f39a02977b8c0c0e65160ef17039bb63"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "UPX 0.80 to 1.24"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={6A 60 68 60 02 4B 00 E8 8B 04 00 00 83 65 FC 00 8D 45 90 50 FF 15 8C F1 48 00 C7 45 FC FE FF FF FF BF 94 00 00 00 57}
        
    condition:
        $str1 at (pe.entry_point)
}

rule upx_1_00_to_1_07 : Packer
{
    meta:
        id = "2V229XAvPOFt5sRXiI40iA"
        fingerprint = "v1_sha256_3fe18ef39b2eca68cc9a9024a930bb479ccf3e0d01a0eb65dead68ab1c76c71a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "UPX 1.00 to 1.07"
        category = "INFO"
        date_create = "19/03/2013"

    strings:
        $str1={60 BE 00 ?0 4? 00 8D BE 00 B0 F? FF ?7 8? [3] ?0 9? [0-9] 90 90 90 90 [0-2] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0}
        
    condition:
        $str1 at (pe.entry_point)
}

rule upx_3 : Packer
{
    meta:
        id = "71kknBB5biSs6kmxENZJHA"
        fingerprint = "v1_sha256_411875993a414c6b37392229018e42eaf55fd98289e364f7b5e2adb6d5db277c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "UPX 3.X"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={60 BE 00 [2] 00 8D BE 00 [2] FF [1-12] EB 1? 90 90 90 90 90 [1-3] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01}
        
    condition:
        $str1 at (pe.entry_point)
}

rule obsidium : Packer
{
    meta:
        id = "2qt4Ii96TOSFtTs3hxorGw"
        fingerprint = "v1_sha256_24691470e25e26f6c95a2c15e7dec5934e231c8175435378f67c964a1624595e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Obsidium"
        category = "INFO"
        date_create = "21/01/2013"
        last_edit = "17/03/2013"

    strings:
        $str1={EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04} /*EntryPoint*/
        
    condition:
        $str1 at (pe.entry_point)
}

rule pecompact2 : Packer
{
    meta:
        id = "5nyYCKC0AsYDRBEcAA4Ogg"
        fingerprint = "v1_sha256_d32df313a154dc3e5a957efdf487b9bdcc8f94c6e110101c7d186dad2a75c363"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "PECompact"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43} /*EntryPoint*/
        
    condition:
        $str1 at (pe.entry_point)
}

rule aspack : Packer
{
    meta:
        id = "65v5bD78jxCTgk4GcJGzrO"
        fingerprint = "v1_sha256_04fa60adc7bdbe2ebfa738d5b1c5054c361512c5d89be4c827cf9e0e5e19bb7e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "ASPack"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={60 E8 00 00 00 00 5D 81 ED 5D 3B 40 00 64 A1 30 00 00 00 0F B6 40 02 0A C0 74 04 33 C0 87 00 B9 ?? ?? 00 00 8D BD B7 3B 40 00 8B F7 AC} /*EntryPoint*/
        
    condition:
        $str1 at (pe.entry_point)
}

rule execryptor : Protector
{
    meta:
        id = "ZOuDPf9VsSooNGRwEktZH"
        fingerprint = "v1_sha256_045d948df98ce6caa34be444d8aafab2c5a1db1b514a928fcad74d24a64c5f79"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "EXECryptor"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 64 8F 05 00 00 00 00} /*EntryPoint*/
        
    condition:
        $str1 at (pe.entry_point)
}

rule winrar_sfx : Packer
{
    meta:
        id = "NLze5VSFLnrgFizzHMQWw"
        fingerprint = "v1_sha256_a3d313cb838b04502d521e02a97016e37f04d259c86512f8ee51c3492a224f3e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Winrar SFX Archive"
        category = "INFO"
        date_create = "18/03/2013"

    strings:
        $signature1={00 00 53 6F 66 74 77 61 72 65 5C 57 69 6E 52 41 52 20 53 46 58 00} 
        
    condition:
        $signature1
}

rule mpress_2_xx_x86 : Packer
{
    meta:
        id = "4kgmZIBmHB5qocmnkz2Fz9"
        fingerprint = "v1_sha256_56e682de781b3c257169f155e4512bd461df3ccb3c4845daa9dd56454f289623"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "MPRESS v2.XX x86  - no .NET"
        category = "INFO"
        date_create = "19/03/2013"
        last_edit = "24/03/2013"

    strings:
        $signature1={60 E8 00 00 00 00 58 05 [2] 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6}
        
    condition:
        $signature1 at (pe.entry_point)
}

rule mpress_2_xx_x64 : Packer
{
    meta:
        id = "BVZmqR6E1BkzRQbagfHb7"
        fingerprint = "v1_sha256_df922c177f7483092c7af4606e18edf283063d706cff0845832df315e151c8f0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "MPRESS v2.XX x64  - no .NET"
        category = "INFO"
        date_create = "19/03/2013"
        last_edit = "24/03/2013"

    strings:
        $signature1={57 56 53 51 52 41 50 48 8D 05 DE 0A 00 00 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 0C 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 06 88 04 31} 
        
    condition:
        $signature1 at (pe.entry_point)
}

rule mpress_2_xx_net : Packer
{
    meta:
        id = "6h4y71OLdtOeb6lX49VHLt"
        fingerprint = "v1_sha256_188a8406967892af6e29e92406274db1a29d33bc001beb749293fc59f53c2dfe"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "MPRESS v2.XX .NET"
        category = "INFO"
        date_create = "24/03/2013"

    strings:
        $signature1={21 46 00 69 00 6C 00 65 00 20 00 69 00 73 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 2E 00 00 0D 4D 00 50 00 52 00 45 00 53 00 53 00 00 00 00 00 2D 2D 93 6B 35 04 2E 43 85 EF}
        
    condition:
        $signature1
}

rule rpx_1_xx : Packer
{
    meta:
        id = "2HjXu0baT5YY8Ry3v1w26c"
        fingerprint = "v1_sha256_e19e597c24e042544d1586257e25f9b62925791c4fd2aa10635d0a276852e1f4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "RPX v1.XX"
        category = "INFO"
        date_create = "24/03/2013"

    strings:
        $signature1= "RPX 1."
        $signature2= "Copyright %C2 %A9  20"
        
    condition:
        $signature1 and $signature2
}

rule mew_11_xx : Packer
{
    meta:
        id = "6beWDopL5Sn1HQPvFXX7bp"
        fingerprint = "v1_sha256_e40d0e7b15fedf36bf9c4e9ff7547521f818bc0afc0ddfdfd05056c4ea41ff02"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "MEW 11"
        category = "INFO"
        date_create = "25/03/2013"

    strings:
        $signature1={50 72 6F 63 41 64 64 72 65 73 73 00 E9 [6-7] 00 00 00 00 00 00 00 00 00 [7] 00}
        $signature2="MEW"
        
    condition:
        $signature1 and $signature2
}

rule yoda_crypter_1_2 : Crypter
{
    meta:
        id = "2MNoYhLtatLVfZY1TEChCm"
        fingerprint = "v1_sha256_26098eb17fe5d684fde17c0afa7b6c4266a86c7aaf7ad91979cf9edc6c5177c4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Yoda Crypter 1.2"
        category = "INFO"
        date_create = "15/04/2013"

    strings:
        $signature1={60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC [19] EB 01 [27] AA E2 CC}
        
    condition:
        $signature1 at (pe.entry_point)
}

rule yoda_crypter_1_3 : Crypter
{
    meta:
        id = "7Q6RSmXMXlW5fgRf4djdr9"
        fingerprint = "v1_sha256_9b4b64b8a732b6904b12e14279eb366ce96aa227700515e5670e31d7466e0666"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Yoda Crypter 1.3"
        category = "INFO"
        date_create = "15/04/2013"

    strings:
        $signature1={55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC}
        
    condition:
        $signature1 at (pe.entry_point)
}
