rule win_enfal_auto {

    meta:
        id = "19MLAXU1ALdQIifWvB8YFA"
        fingerprint = "v1_sha256_c231b8446e9ed78bdd8a9cb59296768a0836b06ecc839e3d3e3a25695d5dfcf0"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.enfal."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enfal"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8975ec e8???????? 8b7508 83c424 8d4df0 }
            // n = 5, score = 200
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   83c424               | add                 esp, 0x24
            //   8d4df0               | lea                 ecx, [ebp - 0x10]

        $sequence_1 = { 51 8d8d68ffffff 51 8d8de8fcffff }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   8d8d68ffffff         | lea                 ecx, [ebp - 0x98]
            //   51                   | push                ecx
            //   8d8de8fcffff         | lea                 ecx, [ebp - 0x318]

        $sequence_2 = { ff75ec ffd6 894304 8d4318 50 6a00 68???????? }
            // n = 7, score = 200
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ffd6                 | call                esi
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   8d4318               | lea                 eax, [ebx + 0x18]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_3 = { 837b1800 8945ec 0f86a6000000 894df4 8955f8 8b4dfc }
            // n = 6, score = 200
            //   837b1800             | cmp                 dword ptr [ebx + 0x18], 0
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   0f86a6000000         | jbe                 0xac
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_4 = { 50 e8???????? 83c410 8b461c }
            // n = 4, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]

        $sequence_5 = { 683f000f00 8d8d68feffff 53 51 6803000080 ff5048 85c0 }
            // n = 7, score = 200
            //   683f000f00           | push                0xf003f
            //   8d8d68feffff         | lea                 ecx, [ebp - 0x198]
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   6803000080           | push                0x80000003
            //   ff5048               | call                dword ptr [eax + 0x48]
            //   85c0                 | test                eax, eax

        $sequence_6 = { 8b4df0 8908 ff45fc 8345f804 8b45fc }
            // n = 5, score = 200
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   ff45fc               | inc                 dword ptr [ebp - 4]
            //   8345f804             | add                 dword ptr [ebp - 8], 4
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { 50 897da0 e8???????? 8d45f0 68???????? }
            // n = 5, score = 200
            //   50                   | push                eax
            //   897da0               | mov                 dword ptr [ebp - 0x60], edi
            //   e8????????           |                     
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   68????????           |                     

        $sequence_8 = { ff55d4 85c0 7471 56 8d8554feffff 6a00 }
            // n = 6, score = 200
            //   ff55d4               | call                dword ptr [ebp - 0x2c]
            //   85c0                 | test                eax, eax
            //   7471                 | je                  0x73
            //   56                   | push                esi
            //   8d8554feffff         | lea                 eax, [ebp - 0x1ac]
            //   6a00                 | push                0

        $sequence_9 = { e8???????? 83c444 8d45f0 53 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83c444               | add                 esp, 0x44
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   53                   | push                ebx

    condition:
        7 of them and filesize < 65536
}
