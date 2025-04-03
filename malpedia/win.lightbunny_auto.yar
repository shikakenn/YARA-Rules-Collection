rule win_lightbunny_auto {

    meta:
        id = "2BZrnVcxNb9nwqDixtElJt"
        fingerprint = "v1_sha256_33cbdcbf0c5d4d510f8f905bf01b71c8a0fd5566bc7f248daf644c66992c59c1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.lightbunny."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lightbunny"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 57 8bf9 83f808 7278 807c06ff00 }
            // n = 5, score = 100
            //   57                   | push                edi
            //   8bf9                 | mov                 edi, ecx
            //   83f808               | cmp                 eax, 8
            //   7278                 | jb                  0x7a
            //   807c06ff00           | cmp                 byte ptr [esi + eax - 1], 0

        $sequence_1 = { 0f57c0 b802000000 0f1145ec 668945ec ff15???????? 8945f0 0fb7460c }
            // n = 7, score = 100
            //   0f57c0               | xorps               xmm0, xmm0
            //   b802000000           | mov                 eax, 2
            //   0f1145ec             | movups              xmmword ptr [ebp - 0x14], xmm0
            //   668945ec             | mov                 word ptr [ebp - 0x14], ax
            //   ff15????????         |                     
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   0fb7460c             | movzx               eax, word ptr [esi + 0xc]

        $sequence_2 = { 0f85c5000000 8b85fffeffff 57 8d7b08 3c01 7538 }
            // n = 6, score = 100
            //   0f85c5000000         | jne                 0xcb
            //   8b85fffeffff         | mov                 eax, dword ptr [ebp - 0x101]
            //   57                   | push                edi
            //   8d7b08               | lea                 edi, [ebx + 8]
            //   3c01                 | cmp                 al, 1
            //   7538                 | jne                 0x3a

        $sequence_3 = { 6a04 58 6bc000 c780cca7410002000000 }
            // n = 4, score = 100
            //   6a04                 | push                4
            //   58                   | pop                 eax
            //   6bc000               | imul                eax, eax, 0
            //   c780cca7410002000000     | mov    dword ptr [eax + 0x41a7cc], 2

        $sequence_4 = { 56 8945f0 be10000000 40 8955e4 8b5508 894df4 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   be10000000           | mov                 esi, 0x10
            //   40                   | inc                 eax
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx

        $sequence_5 = { c705????????00000000 e8???????? 83c40c 6a06 6a01 6a02 ff15???????? }
            // n = 7, score = 100
            //   c705????????00000000     |     
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a06                 | push                6
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   ff15????????         |                     

        $sequence_6 = { 69f224100000 81c6???????? 7410 c7460404000000 ff15???????? }
            // n = 5, score = 100
            //   69f224100000         | imul                esi, edx, 0x1024
            //   81c6????????         |                     
            //   7410                 | je                  0x12
            //   c7460404000000       | mov                 dword ptr [esi + 4], 4
            //   ff15????????         |                     

        $sequence_7 = { 83c40c 81ff00010000 7367 8d85fcfdffff 889c3dfcfdffff 50 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   81ff00010000         | cmp                 edi, 0x100
            //   7367                 | jae                 0x69
            //   8d85fcfdffff         | lea                 eax, [ebp - 0x204]
            //   889c3dfcfdffff       | mov                 byte ptr [ebp + edi - 0x204], bl
            //   50                   | push                eax

        $sequence_8 = { 33c0 8d3c9d58ab4100 f00fb10f 8bc8 85c9 740b }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   8d3c9d58ab4100       | lea                 edi, [ebx*4 + 0x41ab58]
            //   f00fb10f             | lock cmpxchg        dword ptr [edi], ecx
            //   8bc8                 | mov                 ecx, eax
            //   85c9                 | test                ecx, ecx
            //   740b                 | je                  0xd

        $sequence_9 = { 8bf0 b902000000 83feff 0f85f7feffff 68???????? e8???????? }
            // n = 6, score = 100
            //   8bf0                 | mov                 esi, eax
            //   b902000000           | mov                 ecx, 2
            //   83feff               | cmp                 esi, -1
            //   0f85f7feffff         | jne                 0xfffffefd
            //   68????????           |                     
            //   e8????????           |                     

    condition:
        7 of them and filesize < 2376704
}
