rule win_neshta_auto {

    meta:
        id = "1WFnPoeQeHjJE18S9nBven"
        fingerprint = "v1_sha256_c2fcc8ef6abb99e2d337b18a019f7609ebb4adf8a3b9b6d939867df0c528c713"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neshta"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 68???????? 64ff30 648920 e8???????? dd5df8 9b 8d45f4 }
            // n = 7, score = 100
            //   68????????           |                     
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   e8????????           |                     
            //   dd5df8               | fstp                qword ptr [ebp - 8]
            //   9b                   | wait                
            //   8d45f4               | lea                 eax, [ebp - 0xc]

        $sequence_1 = { 83c418 6a00 e8???????? 50 807b3c01 0f859e000000 6a00 }
            // n = 7, score = 100
            //   83c418               | add                 esp, 0x18
            //   6a00                 | push                0
            //   e8????????           |                     
            //   50                   | push                eax
            //   807b3c01             | cmp                 byte ptr [ebx + 0x3c], 1
            //   0f859e000000         | jne                 0xa4
            //   6a00                 | push                0

        $sequence_2 = { 55 8bd6 8bc3 e8???????? 59 3bf8 }
            // n = 6, score = 100
            //   55                   | push                ebp
            //   8bd6                 | mov                 edx, esi
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   3bf8                 | cmp                 edi, eax

        $sequence_3 = { 741f 8d85d0feffff 8bd6 e8???????? 8b85d0feffff }
            // n = 5, score = 100
            //   741f                 | je                  0x21
            //   8d85d0feffff         | lea                 eax, [ebp - 0x130]
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     
            //   8b85d0feffff         | mov                 eax, dword ptr [ebp - 0x130]

        $sequence_4 = { 8d45ec 8b4df8 ba???????? e8???????? 8b55ec 58 e8???????? }
            // n = 7, score = 100
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   ba????????           |                     
            //   e8????????           |                     
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   58                   | pop                 eax
            //   e8????????           |                     

        $sequence_5 = { 8d55f8 b908000000 e8???????? 33c0 5a }
            // n = 5, score = 100
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   b908000000           | mov                 ecx, 8
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   5a                   | pop                 edx

        $sequence_6 = { 8bf8 55 8bd6 8bc3 e8???????? }
            // n = 5, score = 100
            //   8bf8                 | mov                 edi, eax
            //   55                   | push                ebp
            //   8bd6                 | mov                 edx, esi
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_7 = { e8???????? 8b4dec 33d2 8bc3 e8???????? 8bc3 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   33d2                 | xor                 edx, edx
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_8 = { 2bf8 8bc1 b990010000 99 f7f9 }
            // n = 5, score = 100
            //   2bf8                 | sub                 edi, eax
            //   8bc1                 | mov                 eax, ecx
            //   b990010000           | mov                 ecx, 0x190
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx

        $sequence_9 = { 33c9 8a08 41 e8???????? 741f 8d85d0feffff 8bd6 }
            // n = 7, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   41                   | inc                 ecx
            //   e8????????           |                     
            //   741f                 | je                  0x21
            //   8d85d0feffff         | lea                 eax, [ebp - 0x130]
            //   8bd6                 | mov                 edx, esi

    condition:
        7 of them and filesize < 229376
}
