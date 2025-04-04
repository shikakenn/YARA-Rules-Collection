rule win_zeus_action_auto {

    meta:
        id = "utE4zDMNidS0qn7ucvZxo"
        fingerprint = "v1_sha256_3c34c6384d3102dcf930744109cb986bdc2576d8925ca3fbe6fecc099028fdf3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.zeus_action."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus_action"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 56 57 ff15???????? 85c0 0f4975e8 57 e8???????? }
            // n = 7, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f4975e8             | cmovns              esi, dword ptr [ebp - 0x18]
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_1 = { 8995c4feffff 8b75f4 4e 0f8494010000 8b83a8020000 83f8ff 0f840d010000 }
            // n = 7, score = 300
            //   8995c4feffff         | mov                 dword ptr [ebp - 0x13c], edx
            //   8b75f4               | mov                 esi, dword ptr [ebp - 0xc]
            //   4e                   | dec                 esi
            //   0f8494010000         | je                  0x19a
            //   8b83a8020000         | mov                 eax, dword ptr [ebx + 0x2a8]
            //   83f8ff               | cmp                 eax, -1
            //   0f840d010000         | je                  0x113

        $sequence_2 = { 731b 2b45d8 6a20 03c8 894df4 5b 85f6 }
            // n = 7, score = 300
            //   731b                 | jae                 0x1d
            //   2b45d8               | sub                 eax, dword ptr [ebp - 0x28]
            //   6a20                 | push                0x20
            //   03c8                 | add                 ecx, eax
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   5b                   | pop                 ebx
            //   85f6                 | test                esi, esi

        $sequence_3 = { 8bec 81ec10050000 53 33db 817d180000a000 56 57 }
            // n = 7, score = 300
            //   8bec                 | mov                 ebp, esp
            //   81ec10050000         | sub                 esp, 0x510
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   817d180000a000       | cmp                 dword ptr [ebp + 0x18], 0xa00000
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_4 = { eb17 897e0c 897e08 897e04 893e 897e2c }
            // n = 6, score = 300
            //   eb17                 | jmp                 0x19
            //   897e0c               | mov                 dword ptr [esi + 0xc], edi
            //   897e08               | mov                 dword ptr [esi + 8], edi
            //   897e04               | mov                 dword ptr [esi + 4], edi
            //   893e                 | mov                 dword ptr [esi], edi
            //   897e2c               | mov                 dword ptr [esi + 0x2c], edi

        $sequence_5 = { d1e9 03c1 99 f7ff 8b7d10 8a4f0c d3e0 }
            // n = 7, score = 300
            //   d1e9                 | shr                 ecx, 1
            //   03c1                 | add                 eax, ecx
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   8a4f0c               | mov                 cl, byte ptr [edi + 0xc]
            //   d3e0                 | shl                 eax, cl

        $sequence_6 = { 8d1c79 3bcb 7320 8b5508 0fb706 83c602 668b0442 }
            // n = 7, score = 300
            //   8d1c79               | lea                 ebx, [ecx + edi*2]
            //   3bcb                 | cmp                 ecx, ebx
            //   7320                 | jae                 0x22
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0fb706               | movzx               eax, word ptr [esi]
            //   83c602               | add                 esi, 2
            //   668b0442             | mov                 ax, word ptr [edx + eax*2]

        $sequence_7 = { 59 89442408 85c0 7506 40 e9???????? e8???????? }
            // n = 7, score = 300
            //   59                   | pop                 ecx
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   85c0                 | test                eax, eax
            //   7506                 | jne                 8
            //   40                   | inc                 eax
            //   e9????????           |                     
            //   e8????????           |                     

        $sequence_8 = { 1bc0 f7d8 59 59 7514 3974240c 740e }
            // n = 7, score = 300
            //   1bc0                 | sbb                 eax, eax
            //   f7d8                 | neg                 eax
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   7514                 | jne                 0x16
            //   3974240c             | cmp                 dword ptr [esp + 0xc], esi
            //   740e                 | je                  0x10

        $sequence_9 = { 53 56 8b35???????? 57 68???????? ff7508 8d85a4fbffff }
            // n = 7, score = 300
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b35????????         |                     
            //   57                   | push                edi
            //   68????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8d85a4fbffff         | lea                 eax, [ebp - 0x45c]

    condition:
        7 of them and filesize < 827392
}
