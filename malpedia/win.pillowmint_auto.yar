rule win_pillowmint_auto {

    meta:
        id = "7VjCvSZZjiQZhGbXVWuPnF"
        fingerprint = "v1_sha256_ae66a0e7e95b7c87f1f3ab1ab6c5145cf23dd8e31b81c9730156e18b839d9281"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pillowmint."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pillowmint"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 488bd8 488bc8 e8???????? c743203f000000 488d4b28 488d1568f20100 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bd8               | lea                 edx, [esp + 0x40]
            //   488bc8               | nop                 
            //   e8????????           |                     
            //   c743203f000000       | dec                 eax
            //   488d4b28             | mov                 ecx, eax
            //   488d1568f20100       | dec                 eax

        $sequence_1 = { 48c745af00000000 c6459f00 4c8bc3 488d4d9f e8???????? 48837df710 }
            // n = 6, score = 100
            //   48c745af00000000     | dec                 eax
            //   c6459f00             | lea                 edx, [ebp - 0x38]
            //   4c8bc3               | dec                 eax
            //   488d4d9f             | lea                 ecx, [0x3d353]
            //   e8????????           |                     
            //   48837df710           | nop                 

        $sequence_2 = { 483305???????? 488bcb 488905???????? ff15???????? 488d1575970100 483305???????? 488bcb }
            // n = 7, score = 100
            //   483305????????       |                     
            //   488bcb               | lea                 ecx, [esp + 0x60]
            //   488905????????       |                     
            //   ff15????????         |                     
            //   488d1575970100       | dec                 eax
            //   483305????????       |                     
            //   488bcb               | mov                 ecx, dword ptr [ecx + eax*8]

        $sequence_3 = { 488bcb ff15???????? 488d8dc0020000 ff15???????? 80bd8002000000 7415 488d8d80020000 }
            // n = 7, score = 100
            //   488bcb               | lea                 ecx, [edx + 0x1a0]
            //   ff15????????         |                     
            //   488d8dc0020000       | dec                 eax
            //   ff15????????         |                     
            //   80bd8002000000       | lea                 ecx, [edx + 0x90]
            //   7415                 | dec                 eax
            //   488d8d80020000       | lea                 ecx, [edx + 0x50]

        $sequence_4 = { 6666660f1f840000000000 48ffce 410fb606 88840c80000000 ffc3 48ffc1 4d8d7601 }
            // n = 7, score = 100
            //   6666660f1f840000000000     | or    ecx, 0xffffffff
            //   48ffce               | inc                 ebp
            //   410fb606             | xor                 eax, eax
            //   88840c80000000       | dec                 eax
            //   ffc3                 | lea                 ecx, [ebp + 0xc0]
            //   48ffc1               | dec                 eax
            //   4d8d7601             | add                 ebx, 2

        $sequence_5 = { 7547 448435???????? 753e 498b17 488d0dce5a0200 e8???????? 488b15???????? }
            // n = 7, score = 100
            //   7547                 | dec                 eax
            //   448435????????       |                     
            //   753e                 | mov                 eax, dword ptr [edi + 8]
            //   498b17               | dec                 eax
            //   488d0dce5a0200       | mov                 dword ptr [ebx + 8], eax
            //   e8????????           |                     
            //   488b15????????       |                     

        $sequence_6 = { 488b9d98000000 488b03 488bcb ff5008 488bc8 e8???????? 488b03 }
            // n = 7, score = 100
            //   488b9d98000000       | mov                 ecx, 0xfa0
            //   488b03               | dec                 eax
            //   488bcb               | lea                 ecx, [esp + 0x20]
            //   ff5008               | dec                 eax
            //   488bc8               | lea                 ecx, [esp + 0x20]
            //   e8????????           |                     
            //   488b03               | mov                 ecx, 0xff

        $sequence_7 = { 488b80b0000000 c605????????00 6666660f1f840000000000 33d2 48ffcb 48f7f5 80fa0a }
            // n = 7, score = 100
            //   488b80b0000000       | lea                 edx, [0x294ca]
            //   c605????????00       |                     
            //   6666660f1f840000000000     | dec    eax
            //   33d2                 | lea                 ecx, [ebp + 0xa0]
            //   48ffcb               | nop                 
            //   48f7f5               | dec                 esp
            //   80fa0a               | mov                 eax, eax

        $sequence_8 = { 4c8d1d3d900100 418bca 99 2bc2 d1f8 }
            // n = 5, score = 100
            //   4c8d1d3d900100       | dec                 esp
            //   418bca               | mov                 ebp, dword ptr [ebp - 0x19]
            //   99                   | dec                 eax
            //   2bc2                 | and                 ebx, 0xffffffe0
            //   d1f8                 | dec                 ecx

        $sequence_9 = { 488b0d???????? 488bc3 48894908 488b0d???????? 488909 488b0d???????? 48894910 }
            // n = 7, score = 100
            //   488b0d????????       |                     
            //   488bc3               | dec                 eax
            //   48894908             | mov                 dword ptr [esp + 0x38], 0xf
            //   488b0d????????       |                     
            //   488909               | dec                 eax
            //   488b0d????????       |                     
            //   48894910             | mov                 dword ptr [esp + 0x30], edi

    condition:
        7 of them and filesize < 4667392
}
