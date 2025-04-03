rule win_unidentified_099_auto {

    meta:
        id = "ksTz4RnnpxUYHSyOQMm4L"
        fingerprint = "v1_sha256_05815599a06afec044356539b7fb022948a8fa88c4aa5bb33d6e484e946176ef"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_099."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_099"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4d8bc4 418bd6 498bcf e8???????? 4c8d8df0010000 458bc6 498bd7 }
            // n = 7, score = 100
            //   4d8bc4               | or                  eax, eax
            //   418bd6               | inc                 ecx
            //   498bcf               | shl                 eax, 8
            //   e8????????           |                     
            //   4c8d8df0010000       | inc                 esp
            //   458bc6               | or                  eax, ecx
            //   498bd7               | lea                 eax, [edx + 2]

        $sequence_1 = { c5f35cca c4c173590cc1 4c8d0d158f0000 c5f359c1 c5fb101d???????? }
            // n = 5, score = 100
            //   c5f35cca             | lea                 eax, [esp + 0x50]
            //   c4c173590cc1         | dec                 ecx
            //   4c8d0d158f0000       | mov                 edx, ecx
            //   c5f359c1             | dec                 eax
            //   c5fb101d????????     |                     

        $sequence_2 = { 33d2 488bce ff15???????? 488bce 85c0 0f84be000000 4c8d4c244c }
            // n = 7, score = 100
            //   33d2                 | inc                 ebp
            //   488bce               | xor                 edi, edi
            //   ff15????????         |                     
            //   488bce               | dec                 esp
            //   85c0                 | lea                 esi, [0x1c1b1]
            //   0f84be000000         | dec                 eax
            //   4c8d4c244c           | xor                 eax, esp

        $sequence_3 = { 4883f9ff 7406 ff15???????? 48832300 4883c308 488d050d9e0100 }
            // n = 6, score = 100
            //   4883f9ff             | mov                 ecx, ebp
            //   7406                 | dec                 ecx
            //   ff15????????         |                     
            //   48832300             | xchg                dword ptr [esi + esi*8 + 0x1fa28], eax
            //   4883c308             | dec                 eax
            //   488d050d9e0100       | test                eax, eax

        $sequence_4 = { f7842484000000f8ffffff 4c89b424b8210000 448bf7 0f8651020000 48899c24e0210000 4889ac24e8210000 4889b424f0210000 }
            // n = 7, score = 100
            //   f7842484000000f8ffffff     | inc    eax
            //   4c89b424b8210000     | push                ebx
            //   448bf7               | dec                 eax
            //   0f8651020000         | sub                 esp, 0x20
            //   48899c24e0210000     | dec                 eax
            //   4889ac24e8210000     | mov                 ebx, ecx
            //   4889b424f0210000     | dec                 esp

        $sequence_5 = { 488bf9 498bc2 418be9 48c1f806 488d0db4ee0000 4183e23f }
            // n = 6, score = 100
            //   488bf9               | mov                 ecx, 0x80
            //   498bc2               | dec                 ecx
            //   418be9               | mov                 ecx, esi
            //   48c1f806             | dec                 esp
            //   488d0db4ee0000       | lea                 eax, [ebp + 0x1f0]
            //   4183e23f             | rep stosb           byte ptr es:[edi], al

        $sequence_6 = { 0f1005???????? 0fb7442440 0f1101 66894110 488d4b26 4885c9 }
            // n = 6, score = 100
            //   0f1005????????       |                     
            //   0fb7442440           | add                 esp, 0x660
            //   0f1101               | dec                 eax
            //   66894110             | mov                 ecx, dword ptr [esp + 0x380]
            //   488d4b26             | dec                 eax
            //   4885c9               | xor                 ecx, esp

        $sequence_7 = { b910000000 e8???????? 4c8bc8 488bf8 33c0 }
            // n = 5, score = 100
            //   b910000000           | dec                 eax
            //   e8????????           |                     
            //   4c8bc8               | sub                 esp, 0x20
            //   488bf8               | dec                 eax
            //   33c0                 | mov                 ebx, ecx

        $sequence_8 = { 488b05???????? 4833c4 48898580020000 b940000000 e8???????? }
            // n = 5, score = 100
            //   488b05????????       |                     
            //   4833c4               | dec                 ecx
            //   48898580020000       | mov                 ecx, esi
            //   b940000000           | mov                 dword ptr [esp + 0x30], 0x800000
            //   e8????????           |                     

        $sequence_9 = { c7442470fedcba98 c744247476543210 660f1f440000 49ffc0 42803c0000 75f6 488d55d0 }
            // n = 7, score = 100
            //   c7442470fedcba98     | mov                 eax, 0x4b
            //   c744247476543210     | dec                 eax
            //   660f1f440000         | mov                 edx, ebx
            //   49ffc0               | dec                 eax
            //   42803c0000           | lea                 ecx, [ebp + 0x410]
            //   75f6                 | mov                 byte ptr [ecx + 0x24], al
            //   488d55d0             | jmp                 0x254

    condition:
        7 of them and filesize < 314368
}
