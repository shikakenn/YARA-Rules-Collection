rule win_cryptolocker_auto {

    meta:
        id = "33BejBheE2cEfmmaLQsNhk"
        fingerprint = "v1_sha256_75564b552b8c35eb8b1fab229d91abfa4288be2b05e1664b616963e88f02714a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cryptolocker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptolocker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { f605????????01 753b 68???????? ff15???????? }
            // n = 4, score = 600
            //   f605????????01       |                     
            //   753b                 | jne                 0x3d
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_1 = { 8b45e8 8901 8b45ec 894104 8b45f0 8906 8b45f4 }
            // n = 7, score = 600
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_2 = { 5b 8be5 5d c3 c745fc00000000 8bc6 8945e4 }
            // n = 7, score = 600
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8bc6                 | mov                 eax, esi
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_3 = { e8???????? 85c0 0f85e0000000 8b4514 c70000000000 81ff11010000 }
            // n = 6, score = 600
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f85e0000000         | jne                 0xe6
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   81ff11010000         | cmp                 edi, 0x111

        $sequence_4 = { 33c0 5b 8be5 5d c21800 ff7514 56 }
            // n = 7, score = 600
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c21800               | ret                 0x18
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   56                   | push                esi

        $sequence_5 = { 2bc7 99 2bc2 8bd8 8b4508 d1fb 8b5004 }
            // n = 7, score = 600
            //   2bc7                 | sub                 eax, edi
            //   99                   | cdq                 
            //   2bc2                 | sub                 eax, edx
            //   8bd8                 | mov                 ebx, eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   d1fb                 | sar                 ebx, 1
            //   8b5004               | mov                 edx, dword ptr [eax + 4]

        $sequence_6 = { c20400 8d85acfdffff 50 8d85a4fbffff 50 ff15???????? 894508 }
            // n = 7, score = 600
            //   c20400               | ret                 4
            //   8d85acfdffff         | lea                 eax, [ebp - 0x254]
            //   50                   | push                eax
            //   8d85a4fbffff         | lea                 eax, [ebp - 0x45c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_7 = { 6a02 ff15???????? 83f801 770c }
            // n = 4, score = 600
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   83f801               | cmp                 eax, 1
            //   770c                 | ja                  0xe

        $sequence_8 = { ff15???????? 85c0 7480 8b75ec }
            // n = 4, score = 600
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7480                 | je                  0xffffff82
            //   8b75ec               | mov                 esi, dword ptr [ebp - 0x14]

        $sequence_9 = { 85c0 7509 83c640 3b37 72d5 }
            // n = 5, score = 600
            //   85c0                 | test                eax, eax
            //   7509                 | jne                 0xb
            //   83c640               | add                 esi, 0x40
            //   3b37                 | cmp                 esi, dword ptr [edi]
            //   72d5                 | jb                  0xffffffd7

    condition:
        7 of them and filesize < 778240
}
