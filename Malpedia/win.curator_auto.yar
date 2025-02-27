rule win_curator_auto {

    meta:
        id = "6DISvXu8PG3ISsLoELhrzE"
        fingerprint = "v1_sha256_385564603afac75ab1aef52e96073e79dd684407e092688731815c7fd2379a64"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.curator."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.curator"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488d0d54500300 ff15???????? 488b0d???????? 4533c0 8bd3 ff15???????? 488d0d35500300 }
            // n = 7, score = 200
            //   488d0d54500300       | ret                 
            //   ff15????????         |                     
            //   488b0d????????       |                     
            //   4533c0               | inc                 eax
            //   8bd3                 | push                ebx
            //   ff15????????         |                     
            //   488d0d35500300       | dec                 eax

        $sequence_1 = { 448bcf b906000000 e8???????? 488b4b40 488bd3 e8???????? 488b4b48 }
            // n = 7, score = 200
            //   448bcf               | inc                 esp
            //   b906000000           | cmp                 edx, dword ptr [ebx + 0x6c]
            //   e8????????           |                     
            //   488b4b40             | jge                 0x892
            //   488bd3               | dec                 eax
            //   e8????????           |                     
            //   488b4b48             | mov                 eax, dword ptr [ebx + 0x60]

        $sequence_2 = { 0f8399010000 4c8b4dd8 448b65d0 4c894c2478 488b45c8 488b00 48635010 }
            // n = 7, score = 200
            //   0f8399010000         | cmp                 esi, ecx
            //   4c8b4dd8             | jne                 7
            //   448b65d0             | dec                 eax
            //   4c894c2478           | mov                 eax, dword ptr [edi]
            //   488b45c8             | movups              xmm0, xmmword ptr [eax + 0x70]
            //   488b00               | dec                 eax
            //   48635010             | mov                 eax, dword ptr [eax + 0x90]

        $sequence_3 = { 807cfe4100 740a c644fe4201 e8???????? 4084ed 7427 488b4320 }
            // n = 7, score = 200
            //   807cfe4100           | dec                 eax
            //   740a                 | mov                 edx, dword ptr [esi + 8]
            //   c644fe4201           | jle                 0xe2
            //   e8????????           |                     
            //   4084ed               | dec                 eax
            //   7427                 | mov                 edx, dword ptr [esi + 8]
            //   488b4320             | inc                 ecx

        $sequence_4 = { e8???????? 84c0 0f847e030000 e9???????? 4c8b7c2468 488b4608 488945c0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   84c0                 | pop                 ebp
            //   0f847e030000         | inc                 ecx
            //   e9????????           |                     
            //   4c8b7c2468           | pop                 esp
            //   488b4608             | dec                 ecx
            //   488945c0             | mov                 ecx, esi

        $sequence_5 = { 74c8 488bd3 4c8d05922a0500 83e23f 488bcb 48c1f906 }
            // n = 6, score = 200
            //   74c8                 | test                al, al
            //   488bd3               | jne                 0xb4e
            //   4c8d05922a0500       | dec                 eax
            //   83e23f               | mov                 ecx, ebp
            //   488bcb               | je                  0xa9d
            //   48c1f906             | dec                 esp

        $sequence_6 = { 4c8d357eb80800 488d85a0010000 4533e4 4889442428 488d9580080000 4533c9 4489642420 }
            // n = 7, score = 200
            //   4c8d357eb80800       | mov                 edi, edx
            //   488d85a0010000       | inc                 esp
            //   4533e4               | cmp                 byte ptr [ecx], ch
            //   4889442428           | jne                 0xc9
            //   488d9580080000       | dec                 esp
            //   4533c9               | lea                 esi, [0x3e181]
            //   4489642420           | inc                 esp

        $sequence_7 = { 4883ec28 488d0da9feffff e8???????? 8905???????? 83f8ff 7425 488d156ad20600 }
            // n = 7, score = 200
            //   4883ec28             | sub                 esp, 0x20
            //   488d0da9feffff       | dec                 eax
            //   e8????????           |                     
            //   8905????????         |                     
            //   83f8ff               | mov                 ebp, edx
            //   7425                 | mov                 edx, 0x130
            //   488d156ad20600       | dec                 eax

        $sequence_8 = { 48897c2420 440fb6c0 488bd7 488d4def e8???????? 488d4d0f }
            // n = 6, score = 200
            //   48897c2420           | dec                 esp
            //   440fb6c0             | mov                 edx, dword ptr [esp + 0x88]
            //   488bd7               | xor                 bl, bl
            //   488d4def             | dec                 eax
            //   e8????????           |                     
            //   488d4d0f             | mov                 dword ptr [esp + 0x20], eax

        $sequence_9 = { 0f86cf000000 4183ccff 418bcb 48c1e106 4c89741130 4439741124 0f86a7000000 }
            // n = 7, score = 200
            //   0f86cf000000         | mov                 dword ptr [edi], ecx
            //   4183ccff             | mov                 dword ptr [edi + 0x18], 1
            //   418bcb               | dec                 eax
            //   48c1e106             | lea                 ecx, [edi + 0x20]
            //   4c89741130           | dec                 esp
            //   4439741124           | mov                 dword ptr [ecx + 0x10], esi
            //   0f86a7000000         | xorps               xmm0, xmm0

    condition:
        7 of them and filesize < 1265664
}
