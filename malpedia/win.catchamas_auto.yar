rule win_catchamas_auto {

    meta:
        id = "1BIygbwLFIk3zxc6V9YPUd"
        fingerprint = "v1_sha256_23c971887be94861d8baba1aeb0cd2edf205b86ca05876ee11e3ee91d8d84d51"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.catchamas."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.catchamas"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d5c2438 e8???????? 50 ff15???????? 56 6a00 ff15???????? }
            // n = 7, score = 200
            //   8d5c2438             | lea                 ebx, [esp + 0x38]
            //   e8????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   56                   | push                esi
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_1 = { e8???????? 889c243c010000 8b442428 83c0f0 8d500c }
            // n = 5, score = 200
            //   e8????????           |                     
            //   889c243c010000       | mov                 byte ptr [esp + 0x13c], bl
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   83c0f0               | add                 eax, -0x10
            //   8d500c               | lea                 edx, [eax + 0xc]

        $sequence_2 = { 7c86 5e 5d 57 ff15???????? ff15???????? 5f }
            // n = 7, score = 200
            //   7c86                 | jl                  0xffffff88
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_3 = { 53 ff15???????? b92a000000 be???????? 8d7c2418 f3a5 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   b92a000000           | mov                 ecx, 0x2a
            //   be????????           |                     
            //   8d7c2418             | lea                 edi, [esp + 0x18]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_4 = { 8bff baba000000 663bf2 720a bac0000000 663bf2 760c }
            // n = 7, score = 200
            //   8bff                 | mov                 edi, edi
            //   baba000000           | mov                 edx, 0xba
            //   663bf2               | cmp                 si, dx
            //   720a                 | jb                  0xc
            //   bac0000000           | mov                 edx, 0xc0
            //   663bf2               | cmp                 si, dx
            //   760c                 | jbe                 0xe

        $sequence_5 = { 6a01 8d4c2420 50 8944241c }
            // n = 4, score = 200
            //   6a01                 | push                1
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   50                   | push                eax
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax

        $sequence_6 = { 8b8c2404080000 33cc e8???????? 81c408080000 c3 8d44240c 8bd0 }
            // n = 7, score = 200
            //   8b8c2404080000       | mov                 ecx, dword ptr [esp + 0x804]
            //   33cc                 | xor                 ecx, esp
            //   e8????????           |                     
            //   81c408080000         | add                 esp, 0x808
            //   c3                   | ret                 
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   8bd0                 | mov                 edx, eax

        $sequence_7 = { 53 ff15???????? 33c0 5f 5e 5b 8b8c24c8010000 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8b8c24c8010000       | mov                 ecx, dword ptr [esp + 0x1c8]

        $sequence_8 = { c3 8d44240c 8bd0 2bf2 8a08 880c06 }
            // n = 6, score = 200
            //   c3                   | ret                 
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   8bd0                 | mov                 edx, eax
            //   2bf2                 | sub                 esi, edx
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   880c06               | mov                 byte ptr [esi + eax], cl

        $sequence_9 = { e8???????? 8b35???????? 8b4c2418 833900 0f855d050000 8bd1 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b35????????         |                     
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   833900               | cmp                 dword ptr [ecx], 0
            //   0f855d050000         | jne                 0x563
            //   8bd1                 | mov                 edx, ecx

    condition:
        7 of them and filesize < 368640
}
