rule win_blackmatter_auto {

    meta:
        id = "4iLzSyhOvT9eK3TRTJFV06"
        fingerprint = "v1_sha256_c5598bfcc346f3d5f3d24c66f49b6d8b4e14cf3a3802140e28639e017dd52693"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.blackmatter."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackmatter"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83f803 7409 83f802 0f857c010000 e8???????? 83f83d }
            // n = 6, score = 400
            //   83f803               | cmp                 eax, 3
            //   7409                 | je                  0xb
            //   83f802               | cmp                 eax, 2
            //   0f857c010000         | jne                 0x182
            //   e8????????           |                     
            //   83f83d               | cmp                 eax, 0x3d

        $sequence_1 = { c20400 55 8bec 83c4f0 53 c745fc00000000 c745f800000000 }
            // n = 7, score = 400
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83c4f0               | add                 esp, -0x10
            //   53                   | push                ebx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0

        $sequence_2 = { 837dd800 7505 e9???????? 68???????? e8???????? }
            // n = 5, score = 400
            //   837dd800             | cmp                 dword ptr [ebp - 0x28], 0
            //   7505                 | jne                 7
            //   e9????????           |                     
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 75df 8bc2 5e 5a 5d }
            // n = 5, score = 400
            //   75df                 | jne                 0xffffffe1
            //   8bc2                 | mov                 eax, edx
            //   5e                   | pop                 esi
            //   5a                   | pop                 edx
            //   5d                   | pop                 ebp

        $sequence_4 = { 8945f0 837df000 0f8491000000 ff75f4 ff75f0 }
            // n = 5, score = 400
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   0f8491000000         | je                  0x97
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff75f0               | push                dword ptr [ebp - 0x10]

        $sequence_5 = { 50 8d4302 50 e8???????? a3???????? 6a40 8d85fcfeffff }
            // n = 7, score = 400
            //   50                   | push                eax
            //   8d4302               | lea                 eax, [ebx + 2]
            //   50                   | push                eax
            //   e8????????           |                     
            //   a3????????           |                     
            //   6a40                 | push                0x40
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]

        $sequence_6 = { 7429 8d85f8feffff 50 ff15???????? 85c0 }
            // n = 5, score = 400
            //   7429                 | je                  0x2b
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_7 = { 72df 807d085a 77df b802000000 5d c20400 55 }
            // n = 7, score = 400
            //   72df                 | jb                  0xffffffe1
            //   807d085a             | cmp                 byte ptr [ebp + 8], 0x5a
            //   77df                 | ja                  0xffffffe1
            //   b802000000           | mov                 eax, 2
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   55                   | push                ebp

        $sequence_8 = { 6a00 ff15???????? 8945f0 ff75f4 }
            // n = 4, score = 400
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]

        $sequence_9 = { f7f1 92 3b4508 720b 3b450c }
            // n = 5, score = 400
            //   f7f1                 | div                 ecx
            //   92                   | xchg                eax, edx
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]
            //   720b                 | jb                  0xd
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]

    condition:
        7 of them and filesize < 194560
}
