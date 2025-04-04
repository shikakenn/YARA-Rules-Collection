rule win_citadel_auto {

    meta:
        id = "4dNmNSeitG9aMwEJpIWc7X"
        fingerprint = "v1_sha256_19150147fccb12d09c7c4bd60b0305f74a8937d98e638616a5c6d14e1a34b56b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.citadel."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.citadel"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { eb0e 6800800000 53 57 }
            // n = 4, score = 5100
            //   eb0e                 | jmp                 0x10
            //   6800800000           | push                0x8000
            //   53                   | push                ebx
            //   57                   | push                edi

        $sequence_1 = { 03f7 6a0d 5f e8???????? }
            // n = 4, score = 5000
            //   03f7                 | add                 esi, edi
            //   6a0d                 | push                0xd
            //   5f                   | pop                 edi
            //   e8????????           |                     

        $sequence_2 = { 3d00002003 7715 8b4d08 890e 895604 895e0c }
            // n = 6, score = 5000
            //   3d00002003           | cmp                 eax, 0x3200000
            //   7715                 | ja                  0x17
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   890e                 | mov                 dword ptr [esi], ecx
            //   895604               | mov                 dword ptr [esi + 4], edx
            //   895e0c               | mov                 dword ptr [esi + 0xc], ebx

        $sequence_3 = { ff15???????? 85c0 0f8566010000 57 57 57 57 }
            // n = 7, score = 5000
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8566010000         | jne                 0x16c
            //   57                   | push                edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   57                   | push                edi

        $sequence_4 = { 41 66395802 7405 83c002 }
            // n = 4, score = 5000
            //   41                   | inc                 ecx
            //   66395802             | cmp                 word ptr [eax + 2], bx
            //   7405                 | je                  7
            //   83c002               | add                 eax, 2

        $sequence_5 = { 33c9 663918 7507 41 }
            // n = 4, score = 5000
            //   33c9                 | xor                 ecx, ecx
            //   663918               | cmp                 word ptr [eax], bx
            //   7507                 | jne                 9
            //   41                   | inc                 ecx

        $sequence_6 = { 50 57 e8???????? 33db 3c01 }
            // n = 5, score = 5000
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   3c01                 | cmp                 al, 1

        $sequence_7 = { a1???????? 57 e8???????? 8945fc 3bc3 }
            // n = 5, score = 5000
            //   a1????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   3bc3                 | cmp                 eax, ebx

        $sequence_8 = { 3ac3 73fa 0fb6c0 8b44c104 e9???????? d0e9 }
            // n = 6, score = 3900
            //   3ac3                 | cmp                 al, bl
            //   73fa                 | jae                 0xfffffffc
            //   0fb6c0               | movzx               eax, al
            //   8b44c104             | mov                 eax, dword ptr [ecx + eax*8 + 4]
            //   e9????????           |                     
            //   d0e9                 | shr                 cl, 1

        $sequence_9 = { 0f85a0000000 33c0 85c0 7409 }
            // n = 4, score = 3900
            //   0f85a0000000         | jne                 0xa6
            //   33c0                 | xor                 eax, eax
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb

        $sequence_10 = { 8a4e01 ffd0 884601 33c0 6689460c }
            // n = 5, score = 3900
            //   8a4e01               | mov                 cl, byte ptr [esi + 1]
            //   ffd0                 | call                eax
            //   884601               | mov                 byte ptr [esi + 1], al
            //   33c0                 | xor                 eax, eax
            //   6689460c             | mov                 word ptr [esi + 0xc], ax

        $sequence_11 = { fec8 32d0 8ac2 3245fe 85c9 7408 84db }
            // n = 7, score = 3900
            //   fec8                 | dec                 al
            //   32d0                 | xor                 dl, al
            //   8ac2                 | mov                 al, dl
            //   3245fe               | xor                 al, byte ptr [ebp - 2]
            //   85c9                 | test                ecx, ecx
            //   7408                 | je                  0xa
            //   84db                 | test                bl, bl

        $sequence_12 = { 85c0 740b 8a5608 8a4e02 }
            // n = 4, score = 3900
            //   85c0                 | test                eax, eax
            //   740b                 | je                  0xd
            //   8a5608               | mov                 dl, byte ptr [esi + 8]
            //   8a4e02               | mov                 cl, byte ptr [esi + 2]

        $sequence_13 = { 763c 8a06 2a45ff 8a5602 }
            // n = 4, score = 3900
            //   763c                 | jbe                 0x3e
            //   8a06                 | mov                 al, byte ptr [esi]
            //   2a45ff               | sub                 al, byte ptr [ebp - 1]
            //   8a5602               | mov                 dl, byte ptr [esi + 2]

        $sequence_14 = { 0fb6c9 8b04c8 eb81 d0e9 }
            // n = 4, score = 3900
            //   0fb6c9               | movzx               ecx, cl
            //   8b04c8               | mov                 eax, dword ptr [eax + ecx*8]
            //   eb81                 | jmp                 0xffffff83
            //   d0e9                 | shr                 cl, 1

        $sequence_15 = { e9???????? d0e9 3aca 73fa 0fb6c9 8b04c8 }
            // n = 6, score = 3900
            //   e9????????           |                     
            //   d0e9                 | shr                 cl, 1
            //   3aca                 | cmp                 cl, dl
            //   73fa                 | jae                 0xfffffffc
            //   0fb6c9               | movzx               ecx, cl
            //   8b04c8               | mov                 eax, dword ptr [eax + ecx*8]

    condition:
        7 of them and filesize < 1236992
}
