rule win_duuzer_auto {

    meta:
        id = "6qjq6SBqZYNjbvKrhNba2n"
        fingerprint = "v1_sha256_0a972badbc054d0ce47d3497dce1a043373ba372ad2c5fee4eff7c656c3de915"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.duuzer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.duuzer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83f804 7408 83c8ff e9???????? }
            // n = 4, score = 200
            //   83f804               | cmp                 eax, 4
            //   7408                 | je                  0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     

        $sequence_1 = { 44899d20230000 e8???????? 33c0 488d8dce0f0000 }
            // n = 4, score = 100
            //   44899d20230000       | dec                 esp
            //   e8????????           |                     
            //   33c0                 | mov                 esp, eax
            //   488d8dce0f0000       | inc                 esp

        $sequence_2 = { 40 8985b0cbffff 3bc3 0f8c55fcffff b808000000 }
            // n = 5, score = 100
            //   40                   | je                  0xa
            //   8985b0cbffff         | or                  eax, 0xffffffff
            //   3bc3                 | mov                 dword ptr [ebp - 0x148], 0x4c4e4847
            //   0f8c55fcffff         | mov                 dword ptr [ebp - 0x144], 0x29297e5b
            //   b808000000           | mov                 dword ptr [ebp - 0x140], 0x1b5a5e29

        $sequence_3 = { 488bcb c744242801000000 c744242003000000 ff15???????? 4c8be0 }
            // n = 5, score = 100
            //   488bcb               | dec                 eax
            //   c744242801000000     | mov                 ecx, ebx
            //   c744242003000000     | mov                 dword ptr [esp + 0x28], 1
            //   ff15????????         |                     
            //   4c8be0               | mov                 dword ptr [esp + 0x20], 3

        $sequence_4 = { c78524f4ffff5ae5bef3 c78528f4ffff83f7223e c7852cf4ffff8498990b c78530f4ffffc41f6f89 }
            // n = 4, score = 100
            //   c78524f4ffff5ae5bef3     | dec    eax
            //   c78528f4ffff83f7223e     | cmp    edi, esi
            //   c7852cf4ffff8498990b     | jae    0x2a
            //   c78530f4ffffc41f6f89     | mov    byte ptr [ebx], 0x2e

        $sequence_5 = { 66f3a7 7554 488b0d???????? 488d542420 41b8c0200000 }
            // n = 5, score = 100
            //   66f3a7               | je                  0x16
            //   7554                 | inc                 ecx
            //   488b0d????????       |                     
            //   488d542420           | mov                 ecx, 2
            //   41b8c0200000         | inc                 ebp

        $sequence_6 = { 6800040000 52 e8???????? 8d85f8f7ffff 6a5c }
            // n = 5, score = 100
            //   6800040000           | dec                 eax
            //   52                   | lea                 edx, [esp + 0x20]
            //   e8????????           |                     
            //   8d85f8f7ffff         | inc                 ecx
            //   6a5c                 | mov                 eax, 0x20c0

        $sequence_7 = { 8988180b0000 8d887c0a0000 8988300b0000 33c9 c780200b0000907f4200 }
            // n = 5, score = 100
            //   8988180b0000         | mov                 dword ptr [ebp - 0x13c], 0x71b1a76
            //   8d887c0a0000         | mov                 dword ptr [ebp - 0x138], 0x2965656d
            //   8988300b0000         | push                0x400
            //   33c9                 | push                edx
            //   c780200b0000907f4200     | lea    eax, [ebp - 0x808]

        $sequence_8 = { c785b8feffff47484e4c c785bcfeffff5b7e2929 c785c0feffff295e5a1b c785c4feffff761a1b07 c785c8feffff6d656529 }
            // n = 5, score = 100
            //   c785b8feffff47484e4c     | dec    eax
            //   c785bcfeffff5b7e2929     | cmp    ecx, eax
            //   c785c0feffff295e5a1b     | je    0x11
            //   c785c4feffff761a1b07     | repe cmpsd    dword ptr [esi], dword ptr es:[edi]
            //   c785c8feffff6d656529     | jne    0x56

        $sequence_9 = { c3 53 8b1d???????? 33c9 bf???????? }
            // n = 5, score = 100
            //   c3                   | push                0x5c
            //   53                   | mov                 dword ptr [ebp - 0xbdc], 0xf3bee55a
            //   8b1d????????         |                     
            //   33c9                 | mov                 dword ptr [ebp - 0xbd8], 0x3e22f783
            //   bf????????           |                     

        $sequence_10 = { 488b8ba0000000 488d051b450100 483bc8 7405 e8???????? }
            // n = 5, score = 100
            //   488b8ba0000000       | dec                 esp
            //   488d051b450100       | mov                 dword ptr [esp + 0x20], edi
            //   483bc8               | dec                 eax
            //   7405                 | cmp                 dword ptr [esi + 0x20], edi
            //   e8????????           |                     

        $sequence_11 = { ff15???????? 85db 7e43 488b1d???????? }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   85db                 | mov                 dword ptr [ebp + 0x2320], ebx
            //   7e43                 | xor                 eax, eax
            //   488b1d????????       |                     

        $sequence_12 = { 8d8d843effff 51 52 e8???????? }
            // n = 4, score = 100
            //   8d8d843effff         | dec                 eax
            //   51                   | inc                 ebx
            //   52                   | cmp                 eax, 4
            //   e8????????           |                     

        $sequence_13 = { 41b902000000 4533c0 488bcb e8???????? }
            // n = 4, score = 100
            //   41b902000000         | mov                 dword ptr [esp + 0x68], ebx
            //   4533c0               | dec                 ecx
            //   488bcb               | mov                 edx, esp
            //   e8????????           |                     

        $sequence_14 = { 48895c2468 498bd4 4c897c2420 48397e20 7408 }
            // n = 5, score = 100
            //   48895c2468           | dec                 eax
            //   498bd4               | lea                 ecx, [ebp + 0xfce]
            //   4c897c2420           | test                ebx, ebx
            //   48397e20             | jle                 0x45
            //   7408                 | dec                 eax

    condition:
        7 of them and filesize < 491520
}
