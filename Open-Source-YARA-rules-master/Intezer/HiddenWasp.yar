rule HiddenWasp_Rootkit
{
    meta:
        id = "75nm4S4brl8bNpW24wd4d2"
        fingerprint = "v1_sha256_14c680175a763ca7fb267e3f906bf23e9021b62a0c94c976fe67e93294806fe3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    strings:
        $a1 = { FF D? 89 ?? ?? 83 ?? ?? ?? 0F 84 [0-128] BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D? 48 ?? ?? ?? 48 ?? ?? ?? ?? 74 [0-128] C6 ?? ?? ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? BE ?? ?? ?? ?? }
        $a2 = { 0F 84 [0-128] BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D? }
        $a3 = { 0F B6 ?? 83 ?? ?? 88 ?? 83 [0-128] 8B ?? ?? 3B ?? ?? 0F 82 [0-128] 48 ?? ?? ?? 48 }
        $a4 = { 74 [0-128] C6 ?? ?? ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? BE ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? BF ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D? 89 ?? ?? 83 ?? ?? ?? 0F 84 [0-128] BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D? }
        $b0 = { E8 ?? ?? ?? ?? 83 ?? ?? 83 ?? ?? FF B? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 [0-128] C6 ?? ?? ?? ?? ?? ?? FF 7? ?? 83 ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 ?? ?? 5? 68 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 5? E8 ?? ?? ?? ?? 83 ?? ?? 83 ?? ?? 83 ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 ?? ?? 89 ?? 8D ?? ?? 5? 8D ?? ?? ?? ?? ?? 5? 6A ?? FF D? 83 ?? ?? 89 ?? ?? 83 ?? ?? ?? 0F 84 [0-128] 83 ?? ?? 83 ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 ?? ?? 8D ?? ?? ?? ?? ?? 5? 8D ?? ?? ?? ?? ?? 5? FF D? 83}
        $b1 = { 83 ?? ?? 83 ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 ?? ?? 89 ?? 8D ?? ?? 5? FF 7? ?? 6A ?? FF D? 83 ?? ?? 89 ?? ?? 83 ?? ?? ?? 0F 84 [0-128] 83 ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF 7? ?? 83 ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 ?? ?? 5? 68 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 5? E8 ?? ?? ?? ?? 83 ?? ?? 83 ?? ?? 83 ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 ?? ?? 89 ?? 8D ?? ?? 5? }
        $b2 = { 8B ?? ?? 8B ?? ?? 29 ?? 89 ?? 8B ?? ?? F7 ?? 21 ?? 23 ?? ?? 85 ?? 74 [0-128] 8B ?? ?? 83 ?? ?? 89 ?? ?? 8B ?? ?? 80 3? ?? 75 [0-128] 8B ?? ?? 8B ?? ?? 29}
        $b3 = { 8B ?? ?? 29 ?? 89 ?? 8B ?? ?? F7 ?? 21 ?? 23 ?? ?? 85 ?? 74 [0-128] 8B ?? ?? 83 ?? ?? 89 ?? ?? 8B ?? ?? 80 3? ?? 75 [0-128] 8B}
        $b4 = { 83 ?? ?? 8B ?? ?? 89 ?? ?? 8B ?? ?? 89 [0-128] 8B ?? ?? 89 ?? 8D ?? ?? FF 0? 8A ?? 88 ?? ?? 8B ?? ?? 89 ?? 8D ?? ?? FF 0? 8A ?? 88 ?? ?? 80 7? ?? ?? 75 [0-128] 8A ?? ??}
    condition:
        all of ($a*) or all of ($b*)
}

rule HiddenWasp_Trojan
{
    meta:
        id = "5bK6qpukUpjNEqo8UOyN6x"
        fingerprint = "v1_sha256_c82a4f09006bd5349465e3a3018e071b5d8144063193ad97cb07f6e040ed940c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Intezer Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com"
        copyright = "Intezer Labs"

    strings:
        $a0 = { 5? 5? 5? E8 ?? ?? ?? ?? 8B ?? ?? 29 ?? 89 ?? ?? 89 ?? ?? 8B ?? ?? 8B ?? ?? 29 ?? ?? 29 ?? ?? 83 ?? ?? 8B ?? ?? 8D ?? ?? 89 [0-128] 83 ?? ?? 0F B7 }
        $a1 = { 31 ?? 89 [0-128] FC 88 ?? 89 ?? 89 ?? F2 ?? F7 ?? 4? 66 ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? 89 ?? 89 ?? F2 ?? F7 ?? 4? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? F2 ?? F7 ?? 4? 39 ?? ?? ?? ?? ?? 75 [0-128] BB ?? ?? ?? ?? 31 ?? FC 8B ?? ?? ?? ?? ?? 88 ?? 89 ?? F2 ?? F7 ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? 89 ?? F2 ?? F7 ?? 8D ?? ?? ?? 8B ?? ?? ?? ?? ?? 8D ?? ?? ?? 89 ?? ?? ?? ?? ?? 88 ?? 89 ?? 89 ?? F2 ?? 8B ?? ?? ?? ?? ?? F7 ?? 8D ?? ?? ?? ?? ?? ?? 83 ?? ?? 5? E8 ?? ?? ?? ?? 5? 5? FF 7? ?? FF 7? ?? FF 7? ?? FF 7? ?? FF 7? ?? 5? }
        $a2 = { FF B? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 85 ?? 74 [0-128] 8D ?? ?? FC 89 ?? BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 ?? 75 [0-128] 8B ?? ?? ?? ?? ?? 8B ?? 89 ?? ?? ?? ?? ?? 31 ?? 8B ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? F2 ?? 89 ?? 89 ?? B9 ?? ?? ?? ?? F2 ?? F7 ?? F7 ?? 83 ?? ?? 8D ?? ?? ?? 5? E8 ?? ?? ?? ?? }
        $a3 = { 5? E8 ?? ?? ?? ?? 83 ?? ?? 5? E8 ?? ?? ?? ?? 5? 5? 5? 8D ?? ?? ?? ?? ?? 5? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? 89 ?? ?? 5? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8D ?? ?? B9 ?? ?? ?? ?? 83 ?? ?? 39 ?? 0F 85 [0-128] 83 ?? ?? 68 ?? ?? ?? ?? 83 ?? ?? 68 ?? ?? ?? ?? 5? E8 ?? ?? ?? ?? 83 ?? ?? 5? }
        $a4 = { C6 ?? ?? ?? C6 ?? ?? ?? ?? C6 ?? ?? ?? ?? 8B ?? ?? FC 31 ?? B9 ?? ?? ?? ?? F2 ?? 31 ?? F7 ?? 4? 89 ?? 8D ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 39 ?? 66 ?? 88 ?? AA 7D [0-128] 8B ?? ?? ?? ?? ?? C6 ?? ?? ?? C6 ?? ?? ?? ?? C6 ?? ?? ?? ?? BB ?? ?? ?? ?? 31 ?? FC 89 ?? 89 ?? F2 ?? 89 ?? 8B ?? ?? ?? ?? ?? 89 ?? F2 ?? F7 ?? F7 ?? }
        $a5 = { 81 E? ?? ?? ?? ?? 31 ?? BE ?? ?? ?? ?? FC 88 ?? 8B ?? ?? ?? ?? ?? 89 ?? F2 ?? 89 ?? 8B ?? ?? ?? ?? ?? 89 ?? F2 ?? F7 ?? F7 ?? 8D ?? ?? ?? 5? E8 ?? ?? ?? ?? FF 3? ?? ?? ?? ?? FF 3? ?? ?? ?? ?? 68 ?? ?? ?? ?? 5? 89 ?? E8 ?? ?? ?? ?? 83 ?? ?? 68 ?? ?? ?? ?? 5? E8 ?? ?? ?? ?? 83 ?? ?? 85 ?? 89 ?? 74 [0-128] 5? 68 }
        $a6 = { 0F 86 [0-128] 31 ?? 83 ?? ?? ?? 0F 86 [0-128] 8B ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? 0F B6 ?? ?? ?? D3 ?? 31 ?? 8B ?? ?? 23 ?? ?? 8B ?? ?? 89 ?? ?? 8B ?? ?? 0F B7 ?? ?? 89 ?? ?? }
        $b0 = { EB [0-128] 8B ?? ?? 3B ?? ?? 7C [0-128] 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? }
        $b1 = { ?? 48 ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 ?? 8B ?? ?? 39 ?? 75 [0-128] E8 ?? ?? ?? ?? 83 ?? ?? 74 [0-128] 48 }
        $b2 = { 75 [0-128] 48 ?? ?? ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? B8 ?? ?? ?? ?? FC 48 ?? ?? ?? F2 ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? 83 ?? ?? ?? 79 [0-128] 48 }
        $b3 = { ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? B8 ?? ?? ?? ?? FC 48 ?? ?? ?? F2 ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? 83 ?? ?? ?? 79 [0-128] 48 ?? ?? ?? E8 ?? }
        $b4 = { 0F B6 ?? 48 ?? ?? ?? BE ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 01 ?? 48 ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 0F B7 ?? 66 ?? ?? 83 [0-128] 8B ?? ?? 3B ?? ?? 7C [0-128] 8B ?? ?? 01 ?? 48 ?? 48 ?? ?? ?? C6 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 8B ?? ?? 01 ?? 48 ?? 48 ?? ?? ?? C6 ?? ?? 48 ?? ?? ?? }
        $b5 = { ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? FC 48 ?? ?? ?? ?? ?? ?? F2 ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? FC 48 ?? ?? ?? ?? ?? ?? F2 ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? BE ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 75 [0-128] 48 ?? ?? ?? ?? ?? ?? BA ?? }

    condition:
        all of ($a*) or all of ($b*)
}
