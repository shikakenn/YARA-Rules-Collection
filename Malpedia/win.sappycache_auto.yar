rule win_sappycache_auto {

    meta:
        id = "6ZM9ZrYZsY8SPEqhyS0D9R"
        fingerprint = "v1_sha256_accd6826861cb14b3264b0a3eac9debd4934e0de6f313d816d6bcd533efab795"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sappycache."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sappycache"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 48c1e109 4903cc e8???????? 488b5c2448 83f801 754c 8b542440 }
            // n = 7, score = 200
            //   48c1e109             | lea                 ecx, [0x12b22]
            //   4903cc               | xor                 edx, edx
            //   e8????????           |                     
            //   488b5c2448           | dec                 eax
            //   83f801               | test                eax, eax
            //   754c                 | dec                 eax
            //   8b542440             | cmovne              ecx, eax

        $sequence_1 = { 736c 488bf3 4c8bf3 49c1fe06 4c8d2d36da0000 }
            // n = 5, score = 200
            //   736c                 | mov                 dword ptr [esp + 0x860], eax
            //   488bf3               | xor                 edx, edx
            //   4c8bf3               | dec                 eax
            //   49c1fe06             | lea                 ecx, [esp + 0x60]
            //   4c8d2d36da0000       | dec                 eax

        $sequence_2 = { 8bea 0f1f8000000000 e8???????? 448bf0 }
            // n = 4, score = 200
            //   8bea                 | inc                 esp
            //   0f1f8000000000       | mov                 dword ptr [esp + 0x40], edi
            //   e8????????           |                     
            //   448bf0               | dec                 eax

        $sequence_3 = { 4933d0 4a8794f150800100 eb2d 4c8b05???????? ebb1 }
            // n = 5, score = 200
            //   4933d0               | lea                 ecx, [ebx + ebx*4]
            //   4a8794f150800100     | dec                 eax
            //   eb2d                 | sub                 esp, 0x20
            //   4c8b05????????       |                     
            //   ebb1                 | xor                 ebx, ebx

        $sequence_4 = { 0f84d1fcffff 418bfd 44896d80 498bdd 0f1f440000 33d2 488d8d20420000 }
            // n = 7, score = 200
            //   0f84d1fcffff         | dec                 eax
            //   418bfd               | sub                 esp, 0x20
            //   44896d80             | dec                 eax
            //   498bdd               | lea                 edi, [0x1140f]
            //   0f1f440000           | je                  0x12d
            //   33d2                 | ret                 
            //   488d8d20420000       | dec                 eax

        $sequence_5 = { 488d1541900000 e8???????? 488bd8 4885c0 740f }
            // n = 5, score = 200
            //   488d1541900000       | inc                 ebp
            //   e8????????           |                     
            //   488bd8               | xor                 eax, eax
            //   4885c0               | dec                 eax
            //   740f                 | mov                 dword ptr [esp + 0x20], eax

        $sequence_6 = { 488bcf ff15???????? b801000000 488b6c2440 488b742448 488b7c2450 488b4c2428 }
            // n = 7, score = 200
            //   488bcf               | je                  0x575
            //   ff15????????         |                     
            //   b801000000           | dec                 eax
            //   488b6c2440           | mov                 edx, ebx
            //   488b742448           | dec                 esp
            //   488b7c2450           | lea                 eax, [0xd0a2]
            //   488b4c2428           | and                 edx, 0x3f

        $sequence_7 = { e8???????? 85c0 7407 b902000000 cd29 488d0d434b0100 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   7407                 | lea                 ecx, [ebp + 0x40]
            //   b902000000           | dec                 esp
            //   cd29                 | lea                 eax, [ebp - 0x78]
            //   488d0d434b0100       | mov                 dword ptr [ebp + 0x24], 0x100

        $sequence_8 = { 3b15???????? 7350 488bca 4c8d05f9ca0000 83e13f 488bc2 48c1f806 }
            // n = 7, score = 200
            //   3b15????????         |                     
            //   7350                 | dec                 eax
            //   488bca               | mov                 ecx, esi
            //   4c8d05f9ca0000       | mov                 eax, 1
            //   83e13f               | dec                 eax
            //   488bc2               | mov                 ecx, dword ptr [esp + 0x406c0]
            //   48c1f806             | dec                 eax

        $sequence_9 = { 488d05133c0100 ffcb 488d0c9b 488d0cc8 ff15???????? ff0d???????? 85db }
            // n = 7, score = 200
            //   488d05133c0100       | inc                 ebp
            //   ffcb                 | xor                 ecx, ecx
            //   488d0c9b             | dec                 eax
            //   488d0cc8             | mov                 edx, esi
            //   ff15????????         |                     
            //   ff0d????????         |                     
            //   85db                 | inc                 ebp

    condition:
        7 of them and filesize < 262144
}
