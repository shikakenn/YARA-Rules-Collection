rule win_furtim_auto {

    meta:
        id = "78P6WdEcgwCBzRI9ck3Cmm"
        fingerprint = "v1_sha256_fe578793812b3cd44b1ebd86df72331630f9c46ef93b0c93a291bf5ca64790a1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.furtim."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.furtim"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 33c0 8d7df8 ab 8d45f4 50 8d45dc 50 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8d7df8               | lea                 edi, [ebp - 8]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax

        $sequence_1 = { 5a ff91fc020000 ebd7 5e c3 6a03 e8???????? }
            // n = 7, score = 100
            //   5a                   | pop                 edx
            //   ff91fc020000         | call                dword ptr [ecx + 0x2fc]
            //   ebd7                 | jmp                 0xffffffd9
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   6a03                 | push                3
            //   e8????????           |                     

        $sequence_2 = { 7432 395d08 752d 395df0 7424 8b45f8 68???????? }
            // n = 7, score = 100
            //   7432                 | je                  0x34
            //   395d08               | cmp                 dword ptr [ebp + 8], ebx
            //   752d                 | jne                 0x2f
            //   395df0               | cmp                 dword ptr [ebp - 0x10], ebx
            //   7424                 | je                  0x26
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   68????????           |                     

        $sequence_3 = { 53 8d4dfc 51 53 895dfc ffd0 83f87a }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   8d4dfc               | lea                 ecx, [ebp - 4]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   ffd0                 | call                eax
            //   83f87a               | cmp                 eax, 0x7a

        $sequence_4 = { 7520 8d55d8 8bce ff567c 8d45d8 }
            // n = 5, score = 100
            //   7520                 | jne                 0x22
            //   8d55d8               | lea                 edx, [ebp - 0x28]
            //   8bce                 | mov                 ecx, esi
            //   ff567c               | call                dword ptr [esi + 0x7c]
            //   8d45d8               | lea                 eax, [ebp - 0x28]

        $sequence_5 = { 897dfc 897df8 c745f424000000 ff9650040000 }
            // n = 4, score = 100
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   897df8               | mov                 dword ptr [ebp - 8], edi
            //   c745f424000000       | mov                 dword ptr [ebp - 0xc], 0x24
            //   ff9650040000         | call                dword ptr [esi + 0x450]

        $sequence_6 = { c21000 55 8d6c2488 81ece8000000 53 }
            // n = 5, score = 100
            //   c21000               | ret                 0x10
            //   55                   | push                ebp
            //   8d6c2488             | lea                 ebp, [esp - 0x78]
            //   81ece8000000         | sub                 esp, 0xe8
            //   53                   | push                ebx

        $sequence_7 = { 50 ff93f0030000 8d45f4 50 ff93bc040000 648b3d18000000 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ff93f0030000         | call                dword ptr [ebx + 0x3f0]
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   ff93bc040000         | call                dword ptr [ebx + 0x4bc]
            //   648b3d18000000       | mov                 edi, dword ptr fs:[0x18]

        $sequence_8 = { c7459018334400 c7459420334400 c745982c334400 c7459c38334400 c745a044334400 c745a454334400 c74500???????? }
            // n = 7, score = 100
            //   c7459018334400       | mov                 dword ptr [ebp - 0x70], 0x443318
            //   c7459420334400       | mov                 dword ptr [ebp - 0x6c], 0x443320
            //   c745982c334400       | mov                 dword ptr [ebp - 0x68], 0x44332c
            //   c7459c38334400       | mov                 dword ptr [ebp - 0x64], 0x443338
            //   c745a044334400       | mov                 dword ptr [ebp - 0x60], 0x443344
            //   c745a454334400       | mov                 dword ptr [ebp - 0x5c], 0x443354
            //   c74500????????       |                     

        $sequence_9 = { ff9618050000 5f 5e 5b c9 c20c00 ff7508 }
            // n = 7, score = 100
            //   ff9618050000         | call                dword ptr [esi + 0x518]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20c00               | ret                 0xc
            //   ff7508               | push                dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 622592
}
