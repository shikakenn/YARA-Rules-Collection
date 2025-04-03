rule win_powerpool_auto {

    meta:
        id = "2VRMvRuKxvuJE9EpN7JCTA"
        fingerprint = "v1_sha256_fc225d3ab668ac0553c91764abb5591ff765822f57f79bb166f528bf2dc805b8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.powerpool."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.powerpool"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 743f 85db 743b 8b4304 48 83f814 7732 }
            // n = 7, score = 200
            //   743f                 | je                  0x41
            //   85db                 | test                ebx, ebx
            //   743b                 | je                  0x3d
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   48                   | dec                 eax
            //   83f814               | cmp                 eax, 0x14
            //   7732                 | ja                  0x34

        $sequence_1 = { 0101 8b45ec 8b4d18 5f }
            // n = 4, score = 200
            //   0101                 | add                 dword ptr [ecx], eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4d18               | mov                 ecx, dword ptr [ebp + 0x18]
            //   5f                   | pop                 edi

        $sequence_2 = { 740f 68b80b0000 ffd7 381d???????? 75f1 8b0d???????? }
            // n = 6, score = 200
            //   740f                 | je                  0x11
            //   68b80b0000           | push                0xbb8
            //   ffd7                 | call                edi
            //   381d????????         |                     
            //   75f1                 | jne                 0xfffffff3
            //   8b0d????????         |                     

        $sequence_3 = { 006711 40 0000 0303 }
            // n = 4, score = 200
            //   006711               | add                 byte ptr [edi + 0x11], ah
            //   40                   | inc                 eax
            //   0000                 | add                 byte ptr [eax], al
            //   0303                 | add                 eax, dword ptr [ebx]

        $sequence_4 = { 740f 6a02 68???????? 8d4e14 e8???????? 8b4604 }
            // n = 6, score = 200
            //   740f                 | je                  0x11
            //   6a02                 | push                2
            //   68????????           |                     
            //   8d4e14               | lea                 ecx, [esi + 0x14]
            //   e8????????           |                     
            //   8b4604               | mov                 eax, dword ptr [esi + 4]

        $sequence_5 = { 740f 8b4d0c 51 8b4d08 }
            // n = 4, score = 200
            //   740f                 | je                  0x11
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   51                   | push                ecx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_6 = { 8975ec 8955fc a840 7415 8b4508 8b4df8 8b5df4 }
            // n = 7, score = 200
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   a840                 | test                al, 0x40
            //   7415                 | je                  0x17
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b5df4               | mov                 ebx, dword ptr [ebp - 0xc]

        $sequence_7 = { 013e 017e08 894630 5b }
            // n = 4, score = 200
            //   013e                 | add                 dword ptr [esi], edi
            //   017e08               | add                 dword ptr [esi + 8], edi
            //   894630               | mov                 dword ptr [esi + 0x30], eax
            //   5b                   | pop                 ebx

        $sequence_8 = { 8b6c240c 8b4d00 56 8bf0 8bc1 }
            // n = 5, score = 200
            //   8b6c240c             | mov                 ebp, dword ptr [esp + 0xc]
            //   8b4d00               | mov                 ecx, dword ptr [ebp]
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   8bc1                 | mov                 eax, ecx

        $sequence_9 = { 740f 8bc3 83fe10 7303 }
            // n = 4, score = 200
            //   740f                 | je                  0x11
            //   8bc3                 | mov                 eax, ebx
            //   83fe10               | cmp                 esi, 0x10
            //   7303                 | jae                 5

        $sequence_10 = { 7410 50 6a00 ff15???????? 50 ff15???????? 8b5510 }
            // n = 7, score = 200
            //   7410                 | je                  0x12
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]

        $sequence_11 = { 014140 8b45cc 8bc8 d3ea 8b4df8 }
            // n = 5, score = 200
            //   014140               | add                 dword ptr [ecx + 0x40], eax
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   8bc8                 | mov                 ecx, eax
            //   d3ea                 | shr                 edx, cl
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_12 = { 740f 837dd001 7509 50 }
            // n = 4, score = 200
            //   740f                 | je                  0x11
            //   837dd001             | cmp                 dword ptr [ebp - 0x30], 1
            //   7509                 | jne                 0xb
            //   50                   | push                eax

        $sequence_13 = { 740f 8bcb e8???????? c645ff01 }
            // n = 4, score = 200
            //   740f                 | je                  0x11
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   c645ff01             | mov                 byte ptr [ebp - 1], 1

        $sequence_14 = { 01411c 8b7df0 85c0 742c }
            // n = 4, score = 200
            //   01411c               | add                 dword ptr [ecx + 0x1c], eax
            //   8b7df0               | mov                 edi, dword ptr [ebp - 0x10]
            //   85c0                 | test                eax, eax
            //   742c                 | je                  0x2e

        $sequence_15 = { 005311 40 005d11 40 006711 }
            // n = 5, score = 200
            //   005311               | add                 byte ptr [ebx + 0x11], dl
            //   40                   | inc                 eax
            //   005d11               | add                 byte ptr [ebp + 0x11], bl
            //   40                   | inc                 eax
            //   006711               | add                 byte ptr [edi + 0x11], ah

    condition:
        7 of them and filesize < 819200
}
