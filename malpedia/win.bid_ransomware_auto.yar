rule win_bid_ransomware_auto {

    meta:
        id = "1hWNryQGrNx7MMXkjJm9Ws"
        fingerprint = "v1_sha256_932fef61c31980fb36a4d7c0896110af89987a449be43ee55891fe684dd7e3ac"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bid_ransomware."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bid_ransomware"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 6a00 6a00 68???????? ff75a8 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   ff75a8               | push                dword ptr [ebp - 0x58]

        $sequence_1 = { 83e03f 8a80f6434000 aa 4e }
            // n = 4, score = 200
            //   83e03f               | and                 eax, 0x3f
            //   8a80f6434000         | mov                 al, byte ptr [eax + 0x4043f6]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   4e                   | dec                 esi

        $sequence_2 = { c20400 55 8bec 83c4fc e8???????? b919000000 bb01000000 }
            // n = 7, score = 200
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83c4fc               | add                 esp, -4
            //   e8????????           |                     
            //   b919000000           | mov                 ecx, 0x19
            //   bb01000000           | mov                 ebx, 1

        $sequence_3 = { eb15 ff75f4 e8???????? ff75fc e8???????? }
            // n = 5, score = 200
            //   eb15                 | jmp                 0x17
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     

        $sequence_4 = { 8bc2 c1e80e 83e03f 8a80f6434000 aa 49 7418 }
            // n = 7, score = 200
            //   8bc2                 | mov                 eax, edx
            //   c1e80e               | shr                 eax, 0xe
            //   83e03f               | and                 eax, 0x3f
            //   8a80f6434000         | mov                 al, byte ptr [eax + 0x4043f6]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   49                   | dec                 ecx
            //   7418                 | je                  0x1a

        $sequence_5 = { 8a80f6434000 aa 8bc2 c1e814 83e03f }
            // n = 5, score = 200
            //   8a80f6434000         | mov                 al, byte ptr [eax + 0x4043f6]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8bc2                 | mov                 eax, edx
            //   c1e814               | shr                 eax, 0x14
            //   83e03f               | and                 eax, 0x3f

        $sequence_6 = { ff75a8 e8???????? c7458405000000 c705????????00000000 }
            // n = 4, score = 200
            //   ff75a8               | push                dword ptr [ebp - 0x58]
            //   e8????????           |                     
            //   c7458405000000       | mov                 dword ptr [ebp - 0x7c], 5
            //   c705????????00000000     |     

        $sequence_7 = { 6a00 e8???????? 55 8bec 8b450c }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   e8????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_8 = { 8d85d8fdffff 50 68???????? e8???????? 85c0 0f84e2010000 }
            // n = 6, score = 200
            //   8d85d8fdffff         | lea                 eax, [ebp - 0x228]
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f84e2010000         | je                  0x1e8

        $sequence_9 = { bb01000000 d3e3 23d8 7421 50 51 }
            // n = 6, score = 200
            //   bb01000000           | mov                 ebx, 1
            //   d3e3                 | shl                 ebx, cl
            //   23d8                 | and                 ebx, eax
            //   7421                 | je                  0x23
            //   50                   | push                eax
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 57344
}
