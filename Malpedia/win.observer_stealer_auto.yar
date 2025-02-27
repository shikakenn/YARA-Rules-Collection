rule win_observer_stealer_auto {

    meta:
        id = "4waKjwCIjG3rPp6fHhpmfP"
        fingerprint = "v1_sha256_408c29e400138ccd9118763d2259592c2d4bc7c8429c89ee21feadbbd649bc7c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.observer_stealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.observer_stealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3b742420 7412 8bce e8???????? 6a18 58 03f0 }
            // n = 7, score = 100
            //   3b742420             | cmp                 esi, dword ptr [esp + 0x20]
            //   7412                 | je                  0x14
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   6a18                 | push                0x18
            //   58                   | pop                 eax
            //   03f0                 | add                 esi, eax

        $sequence_1 = { 5d 5b 81c490000000 c24c00 81ecb8000000 83bc24d400000008 }
            // n = 6, score = 100
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   81c490000000         | add                 esp, 0x90
            //   c24c00               | ret                 0x4c
            //   81ecb8000000         | sub                 esp, 0xb8
            //   83bc24d400000008     | cmp                 dword ptr [esp + 0xd4], 8

        $sequence_2 = { e8???????? ff36 8d4c243c e8???????? 8d442420 50 8d44241c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   ff36                 | push                dword ptr [esi]
            //   8d4c243c             | lea                 ecx, [esp + 0x3c]
            //   e8????????           |                     
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   50                   | push                eax
            //   8d44241c             | lea                 eax, [esp + 0x1c]

        $sequence_3 = { 53 55 56 57 83ec18 8d8424b8010000 8bf1 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi
            //   83ec18               | sub                 esp, 0x18
            //   8d8424b8010000       | lea                 eax, [esp + 0x1b8]
            //   8bf1                 | mov                 esi, ecx

        $sequence_4 = { e8???????? cc 8b442408 8b4c2404 830023 8b01 8b50fc }
            // n = 7, score = 100
            //   e8????????           |                     
            //   cc                   | int3                
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   830023               | add                 dword ptr [eax], 0x23
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8b50fc               | mov                 edx, dword ptr [eax - 4]

        $sequence_5 = { 59 b201 8d4c244c e8???????? 83c430 8d4c2460 e8???????? }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   b201                 | mov                 dl, 1
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]
            //   e8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   8d4c2460             | lea                 ecx, [esp + 0x60]
            //   e8????????           |                     

        $sequence_6 = { ab ab ab ab 33c0 895a70 8d7a78 }
            // n = 7, score = 100
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   33c0                 | xor                 eax, eax
            //   895a70               | mov                 dword ptr [edx + 0x70], ebx
            //   8d7a78               | lea                 edi, [edx + 0x78]

        $sequence_7 = { 53 ff15???????? 837c243808 8d442424 0f43442424 50 ff15???????? }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   837c243808           | cmp                 dword ptr [esp + 0x38], 8
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   0f43442424           | cmovae              eax, dword ptr [esp + 0x24]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { 8b9044044400 85d2 75cd 5f c1e604 399e44044400 7407 }
            // n = 7, score = 100
            //   8b9044044400         | mov                 edx, dword ptr [eax + 0x440444]
            //   85d2                 | test                edx, edx
            //   75cd                 | jne                 0xffffffcf
            //   5f                   | pop                 edi
            //   c1e604               | shl                 esi, 4
            //   399e44044400         | cmp                 dword ptr [esi + 0x440444], ebx
            //   7407                 | je                  9

        $sequence_9 = { 50 8d4c241c e8???????? 8d8c24e0000000 8b00 03c5 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   e8????????           |                     
            //   8d8c24e0000000       | lea                 ecx, [esp + 0xe0]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   03c5                 | add                 eax, ebp
            //   50                   | push                eax

    condition:
        7 of them and filesize < 614400
}
