rule win_shadowpad_auto {

    meta:
        id = "5ZFpmE2l0E4GbG93SSpE6Y"
        fingerprint = "v1_sha256_a48ed110f457b6e73e53b15a8712b4e6c99fbab0e15de593c3c355b2a563bc5f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.shadowpad."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shadowpad"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 59 8d75dc a3???????? e8???????? 53 ff15???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8d75dc               | lea                 esi, [ebp - 0x24]
            //   a3????????           |                     
            //   e8????????           |                     
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_1 = { e8???????? 5e c3 8d4648 e8???????? 830eff }
            // n = 6, score = 200
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8d4648               | lea                 eax, [esi + 0x48]
            //   e8????????           |                     
            //   830eff               | or                  dword ptr [esi], 0xffffffff

        $sequence_2 = { 50 6801000080 ffd3 8d442430 50 ff15???????? 393d???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   6801000080           | push                0x80000001
            //   ffd3                 | call                ebx
            //   8d442430             | lea                 eax, [esp + 0x30]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   393d????????         |                     

        $sequence_3 = { 0430 8845f8 8d45f8 50 }
            // n = 4, score = 200
            //   0430                 | add                 al, 0x30
            //   8845f8               | mov                 byte ptr [ebp - 8], al
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax

        $sequence_4 = { 33c0 57 33ff 8945e0 894de4 897dec 894de8 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   897dec               | mov                 dword ptr [ebp - 0x14], edi
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx

        $sequence_5 = { 803c0700 7403 47 ebba 8b4d08 33c0 }
            // n = 6, score = 200
            //   803c0700             | cmp                 byte ptr [edi + eax], 0
            //   7403                 | je                  5
            //   47                   | inc                 edi
            //   ebba                 | jmp                 0xffffffbc
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { c20400 55 8bec 53 57 ff7508 ff15???????? }
            // n = 7, score = 200
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     

        $sequence_7 = { 50 e8???????? 85c0 7594 8d45c0 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7594                 | jne                 0xffffff96
            //   8d45c0               | lea                 eax, [ebp - 0x40]

        $sequence_8 = { 50 ffd6 83f820 7e0a 53 8d8590efffff 50 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   83f820               | cmp                 eax, 0x20
            //   7e0a                 | jle                 0xc
            //   53                   | push                ebx
            //   8d8590efffff         | lea                 eax, [ebp - 0x1070]
            //   50                   | push                eax

        $sequence_9 = { 0fb639 c1ce08 83cf20 03f7 83c102 81f6a3d9357c 663919 }
            // n = 7, score = 200
            //   0fb639               | movzx               edi, byte ptr [ecx]
            //   c1ce08               | ror                 esi, 8
            //   83cf20               | or                  edi, 0x20
            //   03f7                 | add                 esi, edi
            //   83c102               | add                 ecx, 2
            //   81f6a3d9357c         | xor                 esi, 0x7c35d9a3
            //   663919               | cmp                 word ptr [ecx], bx

    condition:
        7 of them and filesize < 188416
}
