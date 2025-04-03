rule win_wslink_auto {

    meta:
        id = "6j3q676hcNUUtBkx5nsSWU"
        fingerprint = "v1_sha256_043911efcdbe30576afee29cea013b6adde98869fbb9875f474aa30d6ea1369e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.wslink."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wslink"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4885db 7409 48ffcb c6040300 75f7 488907 4885c0 }
            // n = 7, score = 100
            //   4885db               | dec                 esp
            //   7409                 | lea                 ecx, [0xab0a3]
            //   48ffcb               | mov                 dword ptr [esp + 0x20], 0x10f
            //   c6040300             | lea                 ecx, [edx - 0x62]
            //   75f7                 | inc                 esp
            //   488907               | lea                 eax, [edx + 6]
            //   4885c0               | xor                 eax, eax

        $sequence_1 = { e8???????? 482be0 498bf9 498bd8 488bf2 488be9 4d85c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   482be0               | cmp                 ebp, eax
            //   498bf9               | cmovg               edi, eax
            //   498bd8               | inc                 ebp
            //   488bf2               | test                ebp, ebp
            //   488be9               | jle                 0xd07
            //   4d85c0               | dec                 eax

        $sequence_2 = { 8bd7 488bc8 e8???????? 4885c0 0f8467010000 3b7b0c 7f05 }
            // n = 7, score = 100
            //   8bd7                 | je                  0x106a
            //   488bc8               | dec                 eax
            //   e8????????           |                     
            //   4885c0               | cmp                 dword ptr [ebp], 0
            //   0f8467010000         | jne                 0x1044
            //   3b7b0c               | inc                 ecx
            //   7f05                 | lea                 ecx, [eax - 0x3e]

        $sequence_3 = { e8???????? 85c0 7476 4d8bcf 4c8bc6 498bd6 488bcb }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | dec                 ebp
            //   7476                 | mov                 ebp, ecx
            //   4d8bcf               | inc                 ecx
            //   4c8bc6               | mov                 ebp, eax
            //   498bd6               | inc                 esp
            //   488bcb               | mov                 esi, edx

        $sequence_4 = { e8???????? 4c8b4308 4d85c0 7412 488d1571ac0900 448bcd 488bce }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4c8b4308             | dec                 eax
            //   4d85c0               | and                 ecx, edx
            //   7412                 | dec                 eax
            //   488d1571ac0900       | mov                 edx, dword ptr [esp + 0x28]
            //   448bcd               | dec                 eax
            //   488bce               | or                  ecx, eax

        $sequence_5 = { c705????????03000000 ff15???????? 488b0d???????? ff15???????? 48891d???????? 488b0d???????? 488d15fa070e00 }
            // n = 7, score = 100
            //   c705????????03000000     |     
            //   ff15????????         |                     
            //   488b0d????????       |                     
            //   ff15????????         |                     
            //   48891d????????       |                     
            //   488b0d????????       |                     
            //   488d15fa070e00       | lea                 edx, [0xb25cc]

        $sequence_6 = { 41ff5248 eb27 ba8c000000 4c8d0d32660800 b906000000 448d420a c74424206c000000 }
            // n = 7, score = 100
            //   41ff5248             | dec                 eax
            //   eb27                 | mov                 ebp, eax
            //   ba8c000000           | dec                 ecx
            //   4c8d0d32660800       | mov                 ecx, ebp
            //   b906000000           | dec                 eax
            //   448d420a             | lea                 edx, [0x8712e]
            //   c74424206c000000     | inc                 ecx

        $sequence_7 = { ffc1 48ffc0 3bca 7cf2 eb11 488d7001 448be5 }
            // n = 7, score = 100
            //   ffc1                 | dec                 eax
            //   48ffc0               | test                eax, eax
            //   3bca                 | je                  0x11db
            //   7cf2                 | dec                 eax
            //   eb11                 | mov                 ecx, dword ptr [esp + 0x90]
            //   488d7001             | dec                 esp
            //   448be5               | mov                 eax, dword ptr [esp + 0x98]

        $sequence_8 = { 7420 ffc3 3bde 7c95 4c8bac24a0000000 448be5 eb19 }
            // n = 7, score = 100
            //   7420                 | dec                 eax
            //   ffc3                 | mov                 dword ptr [esp + 0x10], ebx
            //   3bde                 | push                edi
            //   7c95                 | add                 eax, 0x5f51200
            //   4c8bac24a0000000     | add                 byte ptr [esi], ch
            //   448be5               | cmc                 
            //   eb19                 | add                 eax, 0x5f55000

        $sequence_9 = { ff4f30 488bcb e8???????? 488b7c2460 488bc3 488b5c2470 4883c468 }
            // n = 7, score = 100
            //   ff4f30               | dec                 esp
            //   488bcb               | mov                 eax, dword ptr [esp + 0x88]
            //   e8????????           |                     
            //   488b7c2460           | inc                 ecx
            //   488bc3               | mov                 edx, esi
            //   488b5c2470           | dec                 eax
            //   4883c468             | inc                 ecx

    condition:
        7 of them and filesize < 2007040
}
