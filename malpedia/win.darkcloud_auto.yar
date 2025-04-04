rule win_darkcloud_auto {

    meta:
        id = "5IATxemqEZPHbmSE8ZgziP"
        fingerprint = "v1_sha256_dc797d71bdd72f9d3e0bc969cd3f0b1296fdab9f38aa0a923dd640404b9f8c9b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.darkcloud."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkcloud"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 ff15???????? 8b3d???????? 8b1d???????? 898540ffffff be01000000 3bb540ffffff }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   8b1d????????         |                     
            //   898540ffffff         | mov                 dword ptr [ebp - 0xc0], eax
            //   be01000000           | mov                 esi, 1
            //   3bb540ffffff         | cmp                 esi, dword ptr [ebp - 0xc0]

        $sequence_1 = { 8d8d68ffffff ff15???????? 8d8d68ffffff 51 e8???????? 8bd0 8d8d54ffffff }
            // n = 7, score = 100
            //   8d8d68ffffff         | lea                 ecx, [ebp - 0x98]
            //   ff15????????         |                     
            //   8d8d68ffffff         | lea                 ecx, [ebp - 0x98]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d8d54ffffff         | lea                 ecx, [ebp - 0xac]

        $sequence_2 = { 6a00 51 8bf0 ff15???????? 50 56 6a00 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   56                   | push                esi
            //   6a00                 | push                0

        $sequence_3 = { 898578ffffff c78570ffffff08000000 8d9570ffffff 8d4dac ff15???????? 8d4d8c 51 }
            // n = 7, score = 100
            //   898578ffffff         | mov                 dword ptr [ebp - 0x88], eax
            //   c78570ffffff08000000     | mov    dword ptr [ebp - 0x90], 8
            //   8d9570ffffff         | lea                 edx, [ebp - 0x90]
            //   8d4dac               | lea                 ecx, [ebp - 0x54]
            //   ff15????????         |                     
            //   8d4d8c               | lea                 ecx, [ebp - 0x74]
            //   51                   | push                ecx

        $sequence_4 = { 68???????? ff15???????? 8bd0 8d4dd8 ff15???????? 50 8b4ddc }
            // n = 7, score = 100
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bd0                 | mov                 edx, eax
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]

        $sequence_5 = { 50 8d8da0feffff 51 ff15???????? 50 8d9520feffff 52 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8da0feffff         | lea                 ecx, [ebp - 0x160]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8d9520feffff         | lea                 edx, [ebp - 0x1e0]
            //   52                   | push                edx

        $sequence_6 = { 8d4dd4 ff15???????? 8b55cc 89951cffffff c745cc00000000 }
            // n = 5, score = 100
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   ff15????????         |                     
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]
            //   89951cffffff         | mov                 dword ptr [ebp - 0xe4], edx
            //   c745cc00000000       | mov                 dword ptr [ebp - 0x34], 0

        $sequence_7 = { 8d4da4 898de8feffff eb09 8d55a4 8995e8feffff 8b85e8feffff 8b08 }
            // n = 7, score = 100
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]
            //   898de8feffff         | mov                 dword ptr [ebp - 0x118], ecx
            //   eb09                 | jmp                 0xb
            //   8d55a4               | lea                 edx, [ebp - 0x5c]
            //   8995e8feffff         | mov                 dword ptr [ebp - 0x118], edx
            //   8b85e8feffff         | mov                 eax, dword ptr [ebp - 0x118]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_8 = { 53 56 57 8965f4 c745f8???????? 8b5d08 33ff }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8965f4               | mov                 dword ptr [ebp - 0xc], esp
            //   c745f8????????       |                     
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   33ff                 | xor                 edi, edi

        $sequence_9 = { 50 c78558ffffff80514000 899d50ffffff ffd7 8d8d50ffffff 50 8d5580 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c78558ffffff80514000     | mov    dword ptr [ebp - 0xa8], 0x405180
            //   899d50ffffff         | mov                 dword ptr [ebp - 0xb0], ebx
            //   ffd7                 | call                edi
            //   8d8d50ffffff         | lea                 ecx, [ebp - 0xb0]
            //   50                   | push                eax
            //   8d5580               | lea                 edx, [ebp - 0x80]

    condition:
        7 of them and filesize < 622592
}
