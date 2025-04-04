rule win_ascentloader_auto {

    meta:
        id = "23lkWhchSSdntQ1YmS0BkY"
        fingerprint = "v1_sha256_47183e13937994500473836e864be558b3709bce2edd5ef734fa1f084094231f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ascentloader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ascentloader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d44244c 50 ffd7 8d3c03 }
            // n = 4, score = 100
            //   8d44244c             | lea                 eax, [esp + 0x4c]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8d3c03               | lea                 edi, [ebx + eax]

        $sequence_1 = { 33c0 66894de0 66894de6 51 8d4dc4 }
            // n = 5, score = 100
            //   33c0                 | xor                 eax, eax
            //   66894de0             | mov                 word ptr [ebp - 0x20], cx
            //   66894de6             | mov                 word ptr [ebp - 0x1a], cx
            //   51                   | push                ecx
            //   8d4dc4               | lea                 ecx, [ebp - 0x3c]

        $sequence_2 = { 83c414 85c0 0f84a3010000 817c243400040000 8b5c2410 0f8388010000 85f6 }
            // n = 7, score = 100
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   0f84a3010000         | je                  0x1a9
            //   817c243400040000     | cmp                 dword ptr [esp + 0x34], 0x400
            //   8b5c2410             | mov                 ebx, dword ptr [esp + 0x10]
            //   0f8388010000         | jae                 0x18e
            //   85f6                 | test                esi, esi

        $sequence_3 = { 59 8d8dfcfdffff e8???????? b901020000 }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   8d8dfcfdffff         | lea                 ecx, [ebp - 0x204]
            //   e8????????           |                     
            //   b901020000           | mov                 ecx, 0x201

        $sequence_4 = { 5d c3 b8???????? e8???????? 81eca0060000 53 56 }
            // n = 7, score = 100
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   b8????????           |                     
            //   e8????????           |                     
            //   81eca0060000         | sub                 esp, 0x6a0
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_5 = { 740f 56 ff15???????? 8b4df4 03c8 }
            // n = 5, score = 100
            //   740f                 | je                  0x11
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   03c8                 | add                 ecx, eax

        $sequence_6 = { 56 ff15???????? 8bce e8???????? e8???????? 85c0 743f }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   743f                 | je                  0x41

        $sequence_7 = { 6800800000 53 ff7604 ff15???????? 5b 8bce 5e }
            // n = 7, score = 100
            //   6800800000           | push                0x8000
            //   53                   | push                ebx
            //   ff7604               | push                dword ptr [esi + 4]
            //   ff15????????         |                     
            //   5b                   | pop                 ebx
            //   8bce                 | mov                 ecx, esi
            //   5e                   | pop                 esi

        $sequence_8 = { 8b7508 c7465cc0064100 83660800 33ff }
            // n = 4, score = 100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   c7465cc0064100       | mov                 dword ptr [esi + 0x5c], 0x4106c0
            //   83660800             | and                 dword ptr [esi + 8], 0
            //   33ff                 | xor                 edi, edi

        $sequence_9 = { 56 8b5004 8b00 57 }
            // n = 4, score = 100
            //   56                   | push                esi
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   57                   | push                edi

    condition:
        7 of them and filesize < 253952
}
