rule win_phoreal_auto {

    meta:
        id = "5j4NfpQ6ODL6n0E1Z9NBDs"
        fingerprint = "v1_sha256_904dd636d7db526ab8a0410c75a52ee0fac4292f0f4ce7ff0cd1d42961fa831e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.phoreal."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phoreal"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 8b4b64 8d542418 52 8b5054 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   8b4b64               | mov                 ecx, dword ptr [ebx + 0x64]
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   8b5054               | mov                 edx, dword ptr [eax + 0x54]

        $sequence_1 = { 8bf8 8d4dd4 3bcf 7465 837de808 720c 8b55d4 }
            // n = 7, score = 200
            //   8bf8                 | mov                 edi, eax
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   3bcf                 | cmp                 ecx, edi
            //   7465                 | je                  0x67
            //   837de808             | cmp                 dword ptr [ebp - 0x18], 8
            //   720c                 | jb                  0xe
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]

        $sequence_2 = { 8b1d???????? 8b4510 8b4d0c 50 8b4508 56 8d140f }
            // n = 7, score = 200
            //   8b1d????????         |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8d140f               | lea                 edx, [edi + ecx]

        $sequence_3 = { e8???????? 837dc808 8b45b4 7302 8bc7 50 6a00 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   837dc808             | cmp                 dword ptr [ebp - 0x38], 8
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   7302                 | jae                 4
            //   8bc7                 | mov                 eax, edi
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_4 = { 8bec 83ec38 56 8b7508 8b4660 }
            // n = 5, score = 200
            //   8bec                 | mov                 ebp, esp
            //   83ec38               | sub                 esp, 0x38
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b4660               | mov                 eax, dword ptr [esi + 0x60]

        $sequence_5 = { 0f8460feffff ff432c 8b432c 8b7c2418 89442450 33c0 89442454 }
            // n = 7, score = 200
            //   0f8460feffff         | je                  0xfffffe66
            //   ff432c               | inc                 dword ptr [ebx + 0x2c]
            //   8b432c               | mov                 eax, dword ptr [ebx + 0x2c]
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   89442450             | mov                 dword ptr [esp + 0x50], eax
            //   33c0                 | xor                 eax, eax
            //   89442454             | mov                 dword ptr [esp + 0x54], eax

        $sequence_6 = { ff15???????? 8d8578ffffff 50 8d4de0 51 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   8d8578ffffff         | lea                 eax, [ebp - 0x88]
            //   50                   | push                eax
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   51                   | push                ecx

        $sequence_7 = { 50 ffd6 85c0 7527 ff15???????? 3d0f000980 0f85cb010000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7527                 | jne                 0x29
            //   ff15????????         |                     
            //   3d0f000980           | cmp                 eax, 0x8009000f
            //   0f85cb010000         | jne                 0x1d1

        $sequence_8 = { d1e8 8d1443 53 8db590feffff e8???????? 8bf8 8db550ffffff }
            // n = 7, score = 200
            //   d1e8                 | shr                 eax, 1
            //   8d1443               | lea                 edx, [ebx + eax*2]
            //   53                   | push                ebx
            //   8db590feffff         | lea                 esi, [ebp - 0x170]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   8db550ffffff         | lea                 esi, [ebp - 0xb0]

        $sequence_9 = { 85c0 7422 8b17 8910 8b4f04 894804 8b5708 }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b4f04               | mov                 ecx, dword ptr [edi + 4]
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   8b5708               | mov                 edx, dword ptr [edi + 8]

    condition:
        7 of them and filesize < 622592
}
