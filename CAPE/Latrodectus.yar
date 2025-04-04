rule Latrodectus
{
    meta:
        id = "43fK8Aba7zqJSkcO9AbaBl"
        fingerprint = "v1_sha256_2f98d570bf9a490eecd2807599b93023ccacab86f3b7674f0118bbebd4dd2776"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "enzok"
        description = "Latrodectus Payload"
        category = "INFO"
        hash = "a547cff9991a713535e5c128a0711ca68acf9298cc2220c4ea0685d580f36811"
        cape_type = "Latrodectus Payload"

    strings:
        $fnvhash1 = {C7 04 24 C5 9D 1C 81 48 8B 44 24 20 48 89 44 24 08}
        $fnvhash2 = {8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01}
        $procchk1 = {E8 [3] FF 85 C0 74 [2] FF FF FF FF E9 [4] E8 [4] 89 44 24 ?? E8 [4] 83 F8 4B 73 ?? 83 [3] 06}
        $procchk2 = {72 [2] FF FF FF FF E9 [4] E8 [4] 83 F8 32 73 ?? 83 [3] 06}
        $version = {C7 44 2? ?? 0? 00 00 00 C7 44 2? ?? 0? 00 00 00 C7 44 2? ?? 01 00 00 00 8B}
    condition:
        all of them
}

rule Latrodectus_AES
{
    meta:
        id = "l3701IHwmYIzyKqEBdNvB"
        fingerprint = "v1_sha256_1f00f6f187f15d39a30e15ffd14dae07707141999271ad4ac6a75ff4d93dd54d"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "enzok"
        description = "Latrodectus Payload"
        category = "INFO"
        hash = "5cecb26a3f33c24b92a0c8f6f5175da0664b21d7c4216a41694e4a4cad233ca8"
        cape_type = "Latrodectus Payload"

    strings:
        $fnvhash1 = {C7 04 24 C5 9D 1C 81 48 8B 44 24 20 48 89 44 24 08}
        $fnvhash2 = {8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01}
        $key =  {C6 44 2? ?? ?? [150] C6 44 2? ?? ?? B8 02}
        $aes_ctr_1 = {8B 44 24 ?? FF C8 89 44 24 ?? 83 7C 24 ?? 00 7C ?? 4? 63 44 24 ?? 4? 8B 4C 24 ?? 0F B6 84 01 F0 00 00 00 3D FF 00 00 00}
        $aes_ctr_2 = {48 03 C8 48 8B C1 0F B6 ?? 48 63 4C 24 ?? 0F B6 4C 0C ?? 33 C1 48 8B 4C 24 ?? 48 8B 54 24 ?? 48 03 D1 48 8B CA 88 01}
        $version = {C7 44 2? ?? 0? 00 00 00 C7 44 2? ?? 0? 00 00 00 C7 44 2? ?? 01 00 00 00 8B}
    condition:
        all of them
}
