rule win_tiny_turla_auto {

    meta:
        id = "2ADQjPajLrkUsRLOR3BGyY"
        fingerprint = "v1_sha256_b2b8f5dd8c24eb98beaa2120ec3707c14594804ade8ee0e436beafc526cfc343"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.tiny_turla."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tiny_turla"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7521 488d4c2450 44896d7f e8???????? }
            // n = 4, score = 100
            //   7521                 | mov                 ecx, ebx
            //   488d4c2450           | test                eax, eax
            //   44896d7f             | je                  0x955
            //   e8????????           |                     

        $sequence_1 = { 48c744242000000000 488bd7 ff15???????? 85c0 7540 8b4c2450 }
            // n = 6, score = 100
            //   48c744242000000000     | mov    ecx, dword ptr [edi]
            //   488bd7               | dec                 eax
            //   ff15????????         |                     
            //   85c0                 | lea                 eax, [ecx - 1]
            //   7540                 | dec                 eax
            //   8b4c2450             | cmp                 eax, -3

        $sequence_2 = { e8???????? 488bf8 4885c0 0f8403010000 41b80e000000 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   488bf8               | mov                 dword ptr [ebp + 0x48], edi
            //   4885c0               | dec                 esp
            //   0f8403010000         | mov                 dword ptr [ebp - 0x10], edi
            //   41b80e000000         | dec                 eax

        $sequence_3 = { 4c8be8 4885c0 0f84d8010000 488b5628 }
            // n = 4, score = 100
            //   4c8be8               | dec                 eax
            //   4885c0               | mov                 ecx, dword ptr [ecx + eax*8]
            //   0f84d8010000         | dec                 eax
            //   488b5628             | mov                 ecx, dword ptr [esp + 0x20]

        $sequence_4 = { 4889742458 48897c2430 e8???????? 498907 }
            // n = 4, score = 100
            //   4889742458           | mov                 dword ptr [esp + 0x20], 0
            //   48897c2430           | dec                 eax
            //   e8????????           |                     
            //   498907               | mov                 edx, edi

        $sequence_5 = { 488bcf e8???????? 413bc6 7407 }
            // n = 4, score = 100
            //   488bcf               | pop                 ebx
            //   e8????????           |                     
            //   413bc6               | ret                 
            //   7407                 | dec                 eax

        $sequence_6 = { 66894308 488d5b10 413bfe 72d3 488d5e18 488bcb }
            // n = 6, score = 100
            //   66894308             | dec                 esp
            //   488d5b10             | lea                 ecx, [ebp + 0x38]
            //   413bfe               | dec                 eax
            //   72d3                 | mov                 ecx, dword ptr [esp + 0x58]
            //   488d5e18             | mov                 bl, 1
            //   488bcb               | inc                 ebp

        $sequence_7 = { 740e ff15???????? 48c74310ffffffff 33c0 e9???????? 4533c9 4c8d442450 }
            // n = 7, score = 100
            //   740e                 | mov                 dword ptr [edi], ebp
            //   ff15????????         |                     
            //   48c74310ffffffff     | dec                 ecx
            //   33c0                 | mov                 eax, ebp
            //   e9????????           |                     
            //   4533c9               | inc                 ebp
            //   4c8d442450           | mov                 dword ptr [esp], ebp

        $sequence_8 = { 488bcf e8???????? 8bc8 8bd8 e8???????? 4c8bf0 }
            // n = 6, score = 100
            //   488bcf               | xor                 ecx, ecx
            //   e8????????           |                     
            //   8bc8                 | jb                  0x49
            //   8bd8                 | dec                 eax
            //   e8????????           |                     
            //   4c8bf0               | mov                 ebx, dword ptr [esp + 0x50]

        $sequence_9 = { 488d5e10 488bcb e8???????? 4c8933 32db e9???????? 488bcf }
            // n = 7, score = 100
            //   488d5e10             | dec                 eax
            //   488bcb               | mov                 edx, ecx
            //   e8????????           |                     
            //   4c8933               | dec                 eax
            //   32db                 | lea                 eax, [esp + 0x38]
            //   e9????????           |                     
            //   488bcf               | dec                 eax

    condition:
        7 of them and filesize < 51200
}
