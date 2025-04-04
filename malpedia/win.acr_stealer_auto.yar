rule win_acr_stealer_auto {

    meta:
        id = "CK7tzvSPTj2hNs139Rqkx"
        fingerprint = "v1_sha256_885dd5a2520c2a460bba6eeb3147670a114466803568b2f029aa5eef95499efd"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.acr_stealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acr_stealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 037e78 b900000000 6a1e 134e7c 52 51 898ea4000000 }
            // n = 7, score = 200
            //   037e78               | add                 edi, dword ptr [esi + 0x78]
            //   b900000000           | mov                 ecx, 0
            //   6a1e                 | push                0x1e
            //   134e7c               | adc                 ecx, dword ptr [esi + 0x7c]
            //   52                   | push                edx
            //   51                   | push                ecx
            //   898ea4000000         | mov                 dword ptr [esi + 0xa4], ecx

        $sequence_1 = { 6a16 88850affffff 8d85f8feffff 50 ff7704 888d08ffffff }
            // n = 6, score = 200
            //   6a16                 | push                0x16
            //   88850affffff         | mov                 byte ptr [ebp - 0xf6], al
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   ff7704               | push                dword ptr [edi + 4]
            //   888d08ffffff         | mov                 byte ptr [ebp - 0xf8], cl

        $sequence_2 = { 8955e8 33c0 0fa4c803 53 c1e103 }
            // n = 5, score = 200
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   33c0                 | xor                 eax, eax
            //   0fa4c803             | shld                eax, ecx, 3
            //   53                   | push                ebx
            //   c1e103               | shl                 ecx, 3

        $sequence_3 = { e8???????? 8b55cc 0430 8b4de4 2375ac ff45f8 88040a }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]
            //   0430                 | add                 al, 0x30
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   2375ac               | and                 esi, dword ptr [ebp - 0x54]
            //   ff45f8               | inc                 dword ptr [ebp - 8]
            //   88040a               | mov                 byte ptr [edx + ecx], al

        $sequence_4 = { 81ff???????? 750a e8???????? 83c404 eb12 6a01 }
            // n = 6, score = 200
            //   81ff????????         |                     
            //   750a                 | jne                 0xc
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   eb12                 | jmp                 0x14
            //   6a01                 | push                1

        $sequence_5 = { c786c400000000000000 3bf9 8d96b0000000 1bc9 }
            // n = 4, score = 200
            //   c786c400000000000000     | mov    dword ptr [esi + 0xc4], 0
            //   3bf9                 | cmp                 edi, ecx
            //   8d96b0000000         | lea                 edx, [esi + 0xb0]
            //   1bc9                 | sbb                 ecx, ecx

        $sequence_6 = { c3 5f 5e b84f40902f ba3b6ae19a 5b 8be5 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   b84f40902f           | mov                 eax, 0x2f90404f
            //   ba3b6ae19a           | mov                 edx, 0x9ae16a3b
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_7 = { 3a4101 751a 83fefe 7433 8a4202 3a4102 750d }
            // n = 7, score = 200
            //   3a4101               | cmp                 al, byte ptr [ecx + 1]
            //   751a                 | jne                 0x1c
            //   83fefe               | cmp                 esi, -2
            //   7433                 | je                  0x35
            //   8a4202               | mov                 al, byte ptr [edx + 2]
            //   3a4102               | cmp                 al, byte ptr [ecx + 2]
            //   750d                 | jne                 0xf

        $sequence_8 = { 0f42f8 897a48 0fb74e1c 0fb7461e 03ce 83c02e }
            // n = 6, score = 200
            //   0f42f8               | cmovb               edi, eax
            //   897a48               | mov                 dword ptr [edx + 0x48], edi
            //   0fb74e1c             | movzx               ecx, word ptr [esi + 0x1c]
            //   0fb7461e             | movzx               eax, word ptr [esi + 0x1e]
            //   03ce                 | add                 ecx, esi
            //   83c02e               | add                 eax, 0x2e

        $sequence_9 = { 79e9 8b55f8 41 03c1 2bf9 }
            // n = 5, score = 200
            //   79e9                 | jns                 0xffffffeb
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   41                   | inc                 ecx
            //   03c1                 | add                 eax, ecx
            //   2bf9                 | sub                 edi, ecx

    condition:
        7 of them and filesize < 1246208
}
