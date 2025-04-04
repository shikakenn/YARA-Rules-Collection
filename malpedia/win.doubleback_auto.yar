rule win_doubleback_auto {

    meta:
        id = "1FxveVyapfV9xW8t9qIn4X"
        fingerprint = "v1_sha256_a12a729d1e3eac6cc5269daa7ad2d63c829a0d3d51d586ba012dff78e07be60d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.doubleback."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doubleback"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3dab3f0000 755e b9ad060000 eb57 b9a7060000 eb50 b947060000 }
            // n = 7, score = 400
            //   3dab3f0000           | jns                 0x1987
            //   755e                 | movzx               edx, ax
            //   b9ad060000           | dec                 ecx
            //   eb57                 | mov                 ecx, ebp
            //   b9a7060000           | jmp                 0x19cf
            //   eb50                 | dec                 eax
            //   b947060000           | lea                 edx, [ebx + 2]

        $sequence_1 = { 742a 3d39380000 741c 3dd73a0000 740e 3dab3f0000 755e }
            // n = 7, score = 400
            //   742a                 | mov                 eax, 0x8000
            //   3d39380000           | dec                 eax
            //   741c                 | mov                 ecx, ebp
            //   3dd73a0000           | jmp                 0xdf9
            //   740e                 | dec                 esp
            //   3dab3f0000           | lea                 esp, [ebx + 0x88]
            //   755e                 | dec                 eax

        $sequence_2 = { b9e7050000 eb42 b9e3050000 eb3b b90b070000 eb34 }
            // n = 6, score = 400
            //   b9e7050000           | push                eax
            //   eb42                 | push                esi
            //   b9e3050000           | push                esi
            //   eb3b                 | push                dword ptr [edi + 0x37e]
            //   b90b070000           | lea                 eax, [ebx + 0x2c]
            //   eb34                 | push                eax

        $sequence_3 = { 740e 3dab3f0000 755e b9ad060000 eb57 }
            // n = 5, score = 400
            //   740e                 | mov                 eax, dword ptr [esp + 0x58]
            //   3dab3f0000           | dec                 ecx
            //   755e                 | mov                 dword ptr [esp + ecx*8 + 4], eax
            //   b9ad060000           | inc                 ecx
            //   eb57                 | mov                 eax, dword ptr [esp]

        $sequence_4 = { 741c 3dd73a0000 740e 3dab3f0000 755e b9ad060000 eb57 }
            // n = 7, score = 400
            //   741c                 | mov                 edi, 3
            //   3dd73a0000           | test                eax, eax
            //   740e                 | jne                 0xe8b
            //   3dab3f0000           | inc                 ebp
            //   755e                 | xor                 ecx, ecx
            //   b9ad060000           | xor                 ecx, ecx
            //   eb57                 | call                dword ptr [ebp - 0x10]

        $sequence_5 = { eb49 b9e7050000 eb42 b9e3050000 eb3b b90b070000 eb34 }
            // n = 7, score = 400
            //   eb49                 | dec                 ecx
            //   b9e7050000           | add                 eax, esp
            //   eb42                 | mov                 dword ptr [eax], 0x6f72506d
            //   b9e3050000           | dec                 ecx
            //   eb3b                 | add                 eax, esp
            //   b90b070000           | mov                 dword ptr [eax], 0x74726570
            //   eb34                 | dec                 ecx

        $sequence_6 = { 774f 7446 3d00280000 7438 3d5a290000 }
            // n = 5, score = 400
            //   774f                 | dec                 eax
            //   7446                 | mov                 edi, eax
            //   3d00280000           | dec                 eax
            //   7438                 | test                eax, eax
            //   3d5a290000           | je                  0x203c

        $sequence_7 = { b9e7050000 eb42 b9e3050000 eb3b b90b070000 eb34 2d63450000 }
            // n = 7, score = 400
            //   b9e7050000           | mov                 eax, edi
            //   eb42                 | dec                 esp
            //   b9e3050000           | add                 eax, ebx
            //   eb3b                 | dec                 eax
            //   b90b070000           | and                 dword ptr [esp + 0x20], 0
            //   eb34                 | dec                 esp
            //   2d63450000           | lea                 ecx, [esp + 0x70]

        $sequence_8 = { 3dd73a0000 740e 3dab3f0000 755e b9ad060000 }
            // n = 5, score = 400
            //   3dd73a0000           | dec                 eax
            //   740e                 | mov                 ebx, eax
            //   3dab3f0000           | dec                 eax
            //   755e                 | test                eax, eax
            //   b9ad060000           | je                  0x1233

        $sequence_9 = { 741c 3dd73a0000 740e 3dab3f0000 755e }
            // n = 5, score = 400
            //   741c                 | dec                 eax
            //   3dd73a0000           | mov                 dword ptr [ecx], eax
            //   740e                 | mov                 eax, dword ptr [ebp + 0x48]
            //   3dab3f0000           | dec                 eax
            //   755e                 | mov                 ecx, dword ptr [ebp + 0x58]

    condition:
        7 of them and filesize < 106496
}
