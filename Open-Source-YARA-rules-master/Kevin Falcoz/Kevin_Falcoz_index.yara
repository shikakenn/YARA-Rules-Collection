import "pe"

rule BlackShades : Trojan
{
    meta:
        id = "5bg9svpCMJElUdrLtfEHn"
        fingerprint = "v1_sha256_48a9d0268084f6a720332f645ec66861972d046f2b05cdfe42e94eac737fc52a"
        version = "1.0"
        date = "26/06/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "BlackShades Server"
        category = "INFO"

    strings:
        $signature1={62 73 73 5F 73 65 72 76 65 72}
        $signature2={43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44}
        $signature3={6D 6F 64 49 6E 6A 50 45}
        
    condition:
        $signature1 and $signature2 and $signature3
}

rule Bublik : Downloader
{
    meta:
        id = "6JvdJLcBRDdPukouODieKK"
        fingerprint = "v1_sha256_ea70244a4a4f5497f6ee3898c29920e69acdbbf6f3fc6bc89cdb96297f6cd609"
        version = "1.0"
        date = "29/09/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Bublik Trojan Downloader"
        category = "INFO"

    strings:
        $signature1={63 6F 6E 73 6F 6C 61 73}
        $signature2={63 6C 55 6E 00 69 6E 66 6F 2E 69 6E 69}
        
    condition:
        $signature1 and $signature2
}
/*
URL: https://github.com/0pc0deFR/YaraRules
Developpeur: 0pc0deFR (alias Kevin Falcoz)
compiler.yar contient plusieurs gles permettant d'identifier un compilateur
*/
/*
rule visual_basic_5_6 : Compiler
{
    meta:
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-Rules-Collection"
        category = "INFO"
        author="Kevin Falcoz"
        date_create="24/02/2013"
        description="Miscrosoft Visual Basic 5.0/6.0"
        
    strings:
        $str1={68 ?? ?? ?? 00 E8 ?? FF FF FF 00 00 ?? 00 00 00 30 00 00 00 ?? 00 00 00 00 00 00 00 [16] 00 00 00 00 00 00 01 00} 
    
    condition:
        $str1 at (pe.entry_point)
}
*/

rule visual_studio_net : Compiler
{
    meta:
        id = "gT7eg8ROlDyH1wLUHCiDI"
        fingerprint = "v1_sha256_f707df30ad03e318edc92febed6c5208750be21bdca0cfc32a32c307c96e3981"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Miscrosoft Visual Studio .NET/C#"
        category = "INFO"
        date_create = "24/02/2013"

    strings:
        $str1={FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00} /*EntryPoint*/
    
    condition:
        $str1 at (pe.entry_point)
}
rule visual_c_plus_plus_6 : Compiler
{
    meta:
        id = "1YUDrp8EpUwKakWbiGuof5"
        fingerprint = "v1_sha256_72d4c4edf3e101cb2c7f04f78f9bd79ccce2b9f5aaa450f8d5759123352d0b61"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Miscrosoft Visual C++ 6.0"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={55 8B EC 6A FF 68 [3] 00 68 [3] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC [1] 53 56 57 89 65 E8} /*EntryPoint*/
    
    condition:
        $str1 at (pe.entry_point)
}
rule visual_c_plus_plus_6_sp : Compiler
{
    meta:
        id = "3TOFqy5BPkNhn9vZYUaEgp"
        fingerprint = "v1_sha256_6e62a7c9dc817e4f761b76a97053525dac33c0a4b264740e37f1b369c8b2ef1c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Miscrosoft Visual C++ 6.0 SPx"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={55 8B EC 83 EC 44 56 FF 15 ?? 10 40 00 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E} /*EntryPoint*/
    
    condition:
        $str1 at (pe.entry_point)
}
rule visual_c_plus_plus_7 : Compiler
{
    meta:
        id = "76AyPf47Otdg4bm81JkzZZ"
        fingerprint = "v1_sha256_d8155900141ea89f066c7b6f50349ffd1fa633b8d80b51b0a4fccd20c88ffc5a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Miscrosoft Visual C++ 7.0"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={6A 60 68 [2] 40 00 E8 [2] 00 00 BF 94 00 00 00 8B C7 E8 [4] 89 65 E8 8B F4 89 3E 56 FF 15 [2] 40 00 8B 4E 10 89 0D} /*EntryPoint*/
        $str2={6A 0C 68 [4] E8 [4] 33 C0 40 89 45 E4}
    
    condition:
        $str1 at (pe.entry_point) or $str2 at (pe.entry_point)
}
rule borland_delphi_6_7 : Compiler
{
    meta:
        id = "6pgJtfn1OUj2ZdQ16dnizO"
        fingerprint = "v1_sha256_5f0c831719b4fdb40c481d7ef605397dd26f612561340b71b780febe2d354c01"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Borland Delphi 6.0 - 7.0"
        category = "INFO"
        date_create = "25/02/2013"

    strings:
        $str1={55 8B EC 83 C4 F0 53 B8 [3] 00 E8 [3] FF 8B 1D [3] 00 8B 03 BA [2] 52 00 E8 [2] F6 FF B8 [2] 52 00 E8 [2] FF FF 8B 03 E8} /*EntryPoint*/
        $str2={55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 [0-1] 53 [9-11] FF 33 C0 55 68 [3] 00 64 FF 30 64 89 20} /*EntryPoint*/
    
    condition:
        $str1 at (pe.entry_point) or $str2 at (pe.entry_point)
}

rule Grozlex : Stealer
{
    meta:
        id = "5AsSMXw7lkkavUQLU5LJC4"
        fingerprint = "v1_sha256_a1b1ef88c693ae52bcfd7ce7a7cf51eed7ba7b2e6f0c69a6ac94099dff79919d"
        version = "1.0"
        date = "20/08/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Grozlex Stealer - Possible HCStealer"
        category = "INFO"

    strings:
        $signature={4C 00 6F 00 67 00 73 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 62 00 79 00 20 00 69 00 43 00 6F 00 7A 00 65 00 6E}
    
    condition:
        $signature
}

rule lost_door : Trojan
{
    meta:
        id = "7dpPUTg8gBHWsOdl4Oj5Nk"
        fingerprint = "v1_sha256_632a3932ab5d7086c11b03bc80347c37ef1f967b7d070f7483ba74d17d356175"
        version = "1.0"
        date = "23/02/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Lost Door"
        category = "INFO"

    strings:
        $signature1={45 44 49 54 5F 53 45 52 56 45 52} /*EDIT_SERVER*/
        
    condition:
        $signature1
}

rule upx_0_80_to_1_24 : Packer
{
    meta:
        id = "6fCrlm9ku1JTdqqKgwSARZ"
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
        id = "3kYgSjeouxwK9XzIMSsXKg"
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
        id = "4GkXBmaVU3F3F6xI39COzP"
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
        id = "6h7HpeApgw6HXqOYyFMBlU"
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
        id = "8clcGYypDg8tQL9wxAOQv"
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
        id = "3RiqDb0758XuLpjgw0vOk9"
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
        id = "7KI51zNHZXRifTpTvOm6wT"
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
        id = "7Nhh4q3n7AEE1mOIzUY870"
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
        id = "LR412qfImldm5T1MUva8I"
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
        id = "iD4wqhXP980iU8iBV1og7"
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
        id = "2cKzn48uy9z5WKWtEpb8Yn"
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
        id = "6v8WcdPl47PlE5Usyof5sL"
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
        id = "2WKGWLayENK9261JrBb0tN"
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
        id = "5mxs6gkR0dNekBB9IQbhC0"
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
        id = "5UJww5oDe3j7L7zQ7hVg6M"
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

rule universal_1337_stealer_serveur : Stealer
{
    meta:
        id = "5s93ivrz5oCkQd5JGUdWGX"
        fingerprint = "v1_sha256_1193197c2f85efb99aba802ffe0efd6f10171e4e2db1a2ad44ee75755b182858"
        version = "1.0"
        date = "24/02/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Universal 1337 Stealer Serveur"
        category = "INFO"

    strings:
        $signature1={2A 5B 53 2D 50 2D 4C 2D 49 2D 54 5D 2A} /*[S-P-L-I-T]*/
        $signature2={2A 5B 48 2D 45 2D 52 2D 45 5D 2A} /*[H-E-R-E]*/
        $signature3={46 54 50 7E} /*FTP~*/
        $signature4={7E 31 7E 31 7E 30 7E 30} /*~1~1~0~0*/
        
    condition:
        $signature1 and $signature2 or $signature3 and $signature4
}
rule Wabot : Worm
{
    meta:
        id = "zpLzdXUbl8t8Frfj73G6e"
        fingerprint = "v1_sha256_5374d73e6c255ce7cbb751e5cf811806f14aa45bdc4560fdb2a0715df91dddab"
        version = "1.0"
        date = "14/08/2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Wabot Trojan Worm"
        category = "INFO"

    strings:
        $signature1={43 3A 5C 6D 61 72 69 6A 75 61 6E 61 2E 74 78 74}
        $signature2={73 49 52 43 34}

    condition:
        $signature1 and $signature2
}

rule xtreme_rat : Trojan
{
    meta:
        id = "63UzGii8ATiQzMHTZybjcZ"
        fingerprint = "v1_sha256_fa7e3f735a77f0254c8f388458b5b7ebaf9ae8ba12603041ef410f0010dbc89e"
        version = "1.0"
        date = "23/02/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Xtreme RAT"
        category = "INFO"

    strings:
        $signature1={58 00 54 00 52 00 45 00 4D 00 45} /*X.T.R.E.M.E*/
        
    condition:
        $signature1
}

rule YahLover : Worm
{
    meta:
        id = "2lJksGEdf7dWzTrDe87adt"
        fingerprint = "v1_sha256_11727a467096f6614e69c454e9ac4b5a56229be83fb7103386a2a8be0c180b7f"
        version = "1.0"
        date = "10/06/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "YahLover"
        category = "INFO"

    strings:
        $signature1={42 00 49 00 54 00 52 00 4F 00 54 00 41 00 54 00 45 00 00 00 42 00 49 00 54 00 53 00 48 00 49 00 46 00 54 00 00 00 00 00 42 00 49 00 54 00 58 00 4F 00 52}
        
    condition:
        $signature1
}

rule Zegost : Trojan
{
    meta:
        id = "6Nu9eHM1sRmkTmKgLaJhcq"
        fingerprint = "v1_sha256_5af6561444b7663fbde82d3cbfc6f8f9da52c11a5b90a032d3b81ad4a6a352a7"
        version = "1.0"
        date = "10/06/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Zegost Trojan"
        category = "INFO"

    strings:
        $signature1={39 2F 66 33 30 4C 69 35 75 62 4F 35 44 4E 41 44 44 78 47 38 73 37 36 32 74 71 59 3D}
        $signature2={00 BA DA 22 51 42 6F 6D 65 00}
        
    condition:
        $signature1 and $signature2
}
