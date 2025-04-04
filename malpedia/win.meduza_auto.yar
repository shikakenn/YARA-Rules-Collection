rule win_meduza_auto {

    meta:
        id = "CnmH3VXntdDcAJ8ivr5fZ"
        fingerprint = "v1_sha256_14b88dc41a5c318d90c279963aa5ad461ee65cb9acf5c901876d99dfeb325a5a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.meduza."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meduza"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83f81f 0f87f959fdff 51 52 e8???????? 83c408 c705????????00000000 }
            // n = 7, score = 100
            //   83f81f               | cmp                 eax, 0x1f
            //   0f87f959fdff         | ja                  0xfffd59ff
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   c705????????00000000     |     

        $sequence_1 = { 898ddcfcffff 8d8d80f5ffff 8985d8fcffff 8d5101 660fef8dd0fcffff 0f298d80f5ffff }
            // n = 6, score = 100
            //   898ddcfcffff         | mov                 dword ptr [ebp - 0x324], ecx
            //   8d8d80f5ffff         | lea                 ecx, [ebp - 0xa80]
            //   8985d8fcffff         | mov                 dword ptr [ebp - 0x328], eax
            //   8d5101               | lea                 edx, [ecx + 1]
            //   660fef8dd0fcffff     | pxor                xmm1, xmmword ptr [ebp - 0x330]
            //   0f298d80f5ffff       | movaps              xmmword ptr [ebp - 0xa80], xmm1

        $sequence_2 = { e8???????? c645fc1d 0f57c0 c785d8f6ffff9929e731 c785dcf6ffffa8016d5b 8b85d8f6ffff 8b8ddcf6ffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c645fc1d             | mov                 byte ptr [ebp - 4], 0x1d
            //   0f57c0               | xorps               xmm0, xmm0
            //   c785d8f6ffff9929e731     | mov    dword ptr [ebp - 0x928], 0x31e72999
            //   c785dcf6ffffa8016d5b     | mov    dword ptr [ebp - 0x924], 0x5b6d01a8
            //   8b85d8f6ffff         | mov                 eax, dword ptr [ebp - 0x928]
            //   8b8ddcf6ffff         | mov                 ecx, dword ptr [ebp - 0x924]

        $sequence_3 = { ff15???????? a1???????? 85c0 7407 50 ff15???????? ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   ff15????????         |                     

        $sequence_4 = { 8945dc 8b45d4 03c2 6a00 6800ca9a3b 13cf 51 }
            // n = 7, score = 100
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   03c2                 | add                 eax, edx
            //   6a00                 | push                0
            //   6800ca9a3b           | push                0x3b9aca00
            //   13cf                 | adc                 ecx, edi
            //   51                   | push                ecx

        $sequence_5 = { 8b4114 8b5110 2bc2 3bc7 7218 83791410 8d4201 }
            // n = 7, score = 100
            //   8b4114               | mov                 eax, dword ptr [ecx + 0x14]
            //   8b5110               | mov                 edx, dword ptr [ecx + 0x10]
            //   2bc2                 | sub                 eax, edx
            //   3bc7                 | cmp                 eax, edi
            //   7218                 | jb                  0x1a
            //   83791410             | cmp                 dword ptr [ecx + 0x14], 0x10
            //   8d4201               | lea                 eax, [edx + 1]

        $sequence_6 = { c78540ffffff00000000 c78544ffffff00000000 85f6 7424 83c8ff f00fc14604 751a }
            // n = 7, score = 100
            //   c78540ffffff00000000     | mov    dword ptr [ebp - 0xc0], 0
            //   c78544ffffff00000000     | mov    dword ptr [ebp - 0xbc], 0
            //   85f6                 | test                esi, esi
            //   7424                 | je                  0x26
            //   83c8ff               | or                  eax, 0xffffffff
            //   f00fc14604           | lock xadd           dword ptr [esi + 4], eax
            //   751a                 | jne                 0x1c

        $sequence_7 = { 8b8ddce4ffff 0f288d30e1ffff 898dfcfcffff 8d8d30e1ffff 8985f8fcffff 8d5101 660fef8df0fcffff }
            // n = 7, score = 100
            //   8b8ddce4ffff         | mov                 ecx, dword ptr [ebp - 0x1b24]
            //   0f288d30e1ffff       | movaps              xmm1, xmmword ptr [ebp - 0x1ed0]
            //   898dfcfcffff         | mov                 dword ptr [ebp - 0x304], ecx
            //   8d8d30e1ffff         | lea                 ecx, [ebp - 0x1ed0]
            //   8985f8fcffff         | mov                 dword ptr [ebp - 0x308], eax
            //   8d5101               | lea                 edx, [ecx + 1]
            //   660fef8df0fcffff     | pxor                xmm1, xmmword ptr [ebp - 0x310]

        $sequence_8 = { 894da4 c7855cffffff9d412b44 8b8558ffffff 8b8d5cffffff 0f288d20ffffff 894dac 8d8d20ffffff }
            // n = 7, score = 100
            //   894da4               | mov                 dword ptr [ebp - 0x5c], ecx
            //   c7855cffffff9d412b44     | mov    dword ptr [ebp - 0xa4], 0x442b419d
            //   8b8558ffffff         | mov                 eax, dword ptr [ebp - 0xa8]
            //   8b8d5cffffff         | mov                 ecx, dword ptr [ebp - 0xa4]
            //   0f288d20ffffff       | movaps              xmm1, xmmword ptr [ebp - 0xe0]
            //   894dac               | mov                 dword ptr [ebp - 0x54], ecx
            //   8d8d20ffffff         | lea                 ecx, [ebp - 0xe0]

        $sequence_9 = { 8b4dec c745e8d6352f2b 898590feffff 898d94feffff c745ec4a55cf55 8b45e8 8b4dec }
            // n = 7, score = 100
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   c745e8d6352f2b       | mov                 dword ptr [ebp - 0x18], 0x2b2f35d6
            //   898590feffff         | mov                 dword ptr [ebp - 0x170], eax
            //   898d94feffff         | mov                 dword ptr [ebp - 0x16c], ecx
            //   c745ec4a55cf55       | mov                 dword ptr [ebp - 0x14], 0x55cf554a
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

    condition:
        7 of them and filesize < 1433600
}
