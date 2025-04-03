rule win_logpos_auto {

    meta:
        id = "5hhDQBQ6ffK6nyMoLhlSKm"
        fingerprint = "v1_sha256_1f09c571a98b8191fefaf5488e1ffd2ed1ffe04d05c499ee0ffd2f1f5274e533"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.logpos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.logpos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a00 ff15???????? 8945e4 8b450c 8b5510 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]

        $sequence_1 = { 8945fc 837dfc00 75df 8b45fc 89ec 5d }
            // n = 6, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   75df                 | jne                 0xffffffe1
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   89ec                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_2 = { 8f45d8 4c 8b55c8 48 }
            // n = 4, score = 100
            //   8f45d8               | pop                 dword ptr [ebp - 0x28]
            //   4c                   | dec                 esp
            //   8b55c8               | mov                 edx, dword ptr [ebp - 0x38]
            //   48                   | dec                 eax

        $sequence_3 = { a3???????? a1???????? 8b5508 8910 6a20 }
            // n = 5, score = 100
            //   a3????????           |                     
            //   a1????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8910                 | mov                 dword ptr [eax], edx
            //   6a20                 | push                0x20

        $sequence_4 = { b801000000 eb05 b800000000 8945d0 8b45d4 8d50ff 8955d4 }
            // n = 7, score = 100
            //   b801000000           | mov                 eax, 1
            //   eb05                 | jmp                 7
            //   b800000000           | mov                 eax, 0
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   8d50ff               | lea                 edx, [eax - 1]
            //   8955d4               | mov                 dword ptr [ebp - 0x2c], edx

        $sequence_5 = { 83f800 75cb 8b45fc 83f802 7c05 }
            // n = 5, score = 100
            //   83f800               | cmp                 eax, 0
            //   75cb                 | jne                 0xffffffcd
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83f802               | cmp                 eax, 2
            //   7c05                 | jl                  7

        $sequence_6 = { eb05 b800000000 89442410 8b442414 678d50ff 89542414 }
            // n = 6, score = 100
            //   eb05                 | jmp                 7
            //   b800000000           | mov                 eax, 0
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   678d50ff             | lea                 edx, [bx + si - 1]
            //   89542414             | mov                 dword ptr [esp + 0x14], edx

        $sequence_7 = { 85c9 7408 48 89c8 48 8b09 ebf3 }
            // n = 7, score = 100
            //   85c9                 | test                ecx, ecx
            //   7408                 | je                  0xa
            //   48                   | dec                 eax
            //   89c8                 | mov                 eax, ecx
            //   48                   | dec                 eax
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   ebf3                 | jmp                 0xfffffff5

        $sequence_8 = { 4d 89dc 48 0fb610 80fa2e 740b 41 }
            // n = 7, score = 100
            //   4d                   | dec                 ebp
            //   89dc                 | mov                 esp, ebx
            //   48                   | dec                 eax
            //   0fb610               | movzx               edx, byte ptr [eax]
            //   80fa2e               | cmp                 dl, 0x2e
            //   740b                 | je                  0xd
            //   41                   | inc                 ecx

        $sequence_9 = { e8???????? 83c404 83f800 0f8537000000 833d????????00 0f852a000000 837d1400 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83f800               | cmp                 eax, 0
            //   0f8537000000         | jne                 0x3d
            //   833d????????00       |                     
            //   0f852a000000         | jne                 0x30
            //   837d1400             | cmp                 dword ptr [ebp + 0x14], 0

    condition:
        7 of them and filesize < 57344
}
