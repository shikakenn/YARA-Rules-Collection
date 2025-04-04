rule win_sphijacker_auto {

    meta:
        id = "Vl8ZmfrRV5iZL8aLQRmhV"
        fingerprint = "v1_sha256_a99b1a8ce4f2ca018676a9e46f28df0afb5f7a80b3caa10c6423eb9f11e6c670"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sphijacker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sphijacker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488bc3 4c8d3586ae0100 83e03f 488bf3 48c1ee06 488d3cc0 }
            // n = 6, score = 100
            //   488bc3               | mov                 dword ptr [esp + 0x50], edx
            //   4c8d3586ae0100       | xor                 ecx, ecx
            //   83e03f               | dec                 eax
            //   488bf3               | lea                 edx, [0x1e38b]
            //   48c1ee06             | dec                 esp
            //   488d3cc0             | mov                 eax, ecx

        $sequence_1 = { ffc8 8bf8 0fb68c8282d80100 0fb6b48283d80100 33d2 488d1c8d00000000 }
            // n = 6, score = 100
            //   ffc8                 | dec                 esp
            //   8bf8                 | mov                 ecx, dword ptr [esp + 0xd0]
            //   0fb68c8282d80100     | dec                 eax
            //   0fb6b48283d80100     | lea                 ecx, [0x225f6]
            //   33d2                 | inc                 ebp
            //   488d1c8d00000000     | xor                 eax, eax

        $sequence_2 = { 4889442420 488d1527e00100 48c7c102000080 ff15???????? 488b4d18 4c8d4520 488d15fbe00100 }
            // n = 7, score = 100
            //   4889442420           | mov                 dword ptr [esp + 0x28], 4
            //   488d1527e00100       | dec                 eax
            //   48c7c102000080       | lea                 edx, [0x1e25f]
            //   ff15????????         |                     
            //   488b4d18             | dec                 eax
            //   4c8d4520             | lea                 edx, [0x1dcd6]
            //   488d15fbe00100       | inc                 ecx

        $sequence_3 = { 740e 8bd0 488d0dd2e20100 e8???????? 488b442450 }
            // n = 5, score = 100
            //   740e                 | mov                 ecx, esi
            //   8bd0                 | movzx               eax, word ptr [esp + ecx + 0x6c]
            //   488d0dd2e20100       | dec                 eax
            //   e8????????           |                     
            //   488b442450           | cmp                 edi, 0x101

        $sequence_4 = { 488bc3 b9209f0000 6666660f1f840000000000 8030ee 488d4005 4883e901 }
            // n = 6, score = 100
            //   488bc3               | mov                 eax, ecx
            //   b9209f0000           | mov                 eax, 0x5a4d
            //   6666660f1f840000000000     | cmp    word ptr [0xffffcdf1], ax
            //   8030ee               | jne                 0x1883
            //   488d4005             | dec                 eax
            //   4883e901             | arpl                word ptr [0xffffce24], cx

        $sequence_5 = { 4c8bc3 488d8d34030000 898530030000 e8???????? 488d0d95ecfeff 48c1e602 0fb784b980d80100 }
            // n = 7, score = 100
            //   4c8bc3               | mov                 eax, dword ptr [edx + eax*8 + 0x2afc0]
            //   488d8d34030000       | dec                 edx
            //   898530030000         | mov                 eax, dword ptr [eax + edi*8 + 0x28]
            //   e8????????           |                     
            //   488d0d95ecfeff       | dec                 eax
            //   48c1e602             | mov                 dword ptr [ebp - 0x29], eax
            //   0fb784b980d80100     | and                 ecx, 0x3f

        $sequence_6 = { 41b93f000f00 4533c0 4889442420 488d154ddf0100 48c7c102000080 ff15???????? 488b4d18 }
            // n = 7, score = 100
            //   41b93f000f00         | dec                 eax
            //   4533c0               | mov                 ebp, ebx
            //   4889442420           | dec                 eax
            //   488d154ddf0100       | lea                 esi, [0x235af]
            //   48c7c102000080       | dec                 esp
            //   ff15????????         |                     
            //   488b4d18             | lea                 esi, [0x23590]

        $sequence_7 = { 488bce 0f1f4000 0f1f840000000000 0fb7440c6c 6639840d501c0000 }
            // n = 5, score = 100
            //   488bce               | jmp                 0x10d9
            //   0f1f4000             | dec                 eax
            //   0f1f840000000000     | lea                 edx, [0x1003f]
            //   0fb7440c6c           | mov                 eax, 6
            //   6639840d501c0000     | fsubr               dword ptr [esi]

        $sequence_8 = { 4889742410 57 4c8bd2 488d359bd1feff }
            // n = 4, score = 100
            //   4889742410           | dec                 eax
            //   57                   | mov                 ecx, ebp
            //   4c8bd2               | inc                 ebp
            //   488d359bd1feff       | xor                 eax, eax

        $sequence_9 = { 660feb15???????? 660feb0d???????? 4c8d0dd4ac0000 f20f5cca f2410f590cc1 660f28d1 660f28c1 }
            // n = 7, score = 100
            //   660feb15????????     |                     
            //   660feb0d????????     |                     
            //   4c8d0dd4ac0000       | lea                 edi, [0xffffb143]
            //   f20f5cca             | dec                 ecx
            //   f2410f590cc1         | or                  esi, 0xffffffff
            //   660f28d1             | dec                 ebp
            //   660f28c1             | mov                 esp, ecx

    condition:
        7 of them and filesize < 808960
}
