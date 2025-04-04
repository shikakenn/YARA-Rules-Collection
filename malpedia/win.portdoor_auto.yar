rule win_portdoor_auto {

    meta:
        id = "49yY6kBfNSWS6yFhla9Sj5"
        fingerprint = "v1_sha256_979d5d744cc74395bacd5f81861791359824c98484ee261c7c39edba432e34ef"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.portdoor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.portdoor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a73 5b 6a3b 59 6a64 }
            // n = 5, score = 100
            //   6a73                 | push                0x73
            //   5b                   | pop                 ebx
            //   6a3b                 | push                0x3b
            //   59                   | pop                 ecx
            //   6a64                 | push                0x64

        $sequence_1 = { 6a08 8bf1 e8???????? 8bf8 56 }
            // n = 5, score = 100
            //   6a08                 | push                8
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   56                   | push                esi

        $sequence_2 = { ddd8 db2d???????? b801000000 833d????????00 0f8586480000 ba05000000 }
            // n = 6, score = 100
            //   ddd8                 | fstp                st(0)
            //   db2d????????         |                     
            //   b801000000           | mov                 eax, 1
            //   833d????????00       |                     
            //   0f8586480000         | jne                 0x488c
            //   ba05000000           | mov                 edx, 5

        $sequence_3 = { 890497 42 eb1d 84ff 7405 c60000 46 }
            // n = 7, score = 100
            //   890497               | mov                 dword ptr [edi + edx*4], eax
            //   42                   | inc                 edx
            //   eb1d                 | jmp                 0x1f
            //   84ff                 | test                bh, bh
            //   7405                 | je                  7
            //   c60000               | mov                 byte ptr [eax], 0
            //   46                   | inc                 esi

        $sequence_4 = { b001 eb0f 68???????? 56 e8???????? 59 59 }
            // n = 7, score = 100
            //   b001                 | mov                 al, 1
            //   eb0f                 | jmp                 0x11
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_5 = { ff15???????? 6a02 89459c 58 ff750c 66894598 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   6a02                 | push                2
            //   89459c               | mov                 dword ptr [ebp - 0x64], eax
            //   58                   | pop                 eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   66894598             | mov                 word ptr [ebp - 0x68], ax
            //   ff15????????         |                     

        $sequence_6 = { 8d85fcf3ffff 57 53 50 e8???????? }
            // n = 5, score = 100
            //   8d85fcf3ffff         | lea                 eax, [ebp - 0xc04]
            //   57                   | push                edi
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { e8???????? eb85 8b3d???????? 8bcf 8b1d???????? e8???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   eb85                 | jmp                 0xffffff87
            //   8b3d????????         |                     
            //   8bcf                 | mov                 ecx, edi
            //   8b1d????????         |                     
            //   e8????????           |                     

        $sequence_8 = { 83c40c 8d1406 3bcb 773f 8b7704 }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8d1406               | lea                 edx, [esi + eax]
            //   3bcb                 | cmp                 ecx, ebx
            //   773f                 | ja                  0x41
            //   8b7704               | mov                 esi, dword ptr [edi + 4]

        $sequence_9 = { eb41 8b4dec e8???????? 8945f0 eb34 8b4dec }
            // n = 6, score = 100
            //   eb41                 | jmp                 0x43
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   eb34                 | jmp                 0x36
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

    condition:
        7 of them and filesize < 297984
}
