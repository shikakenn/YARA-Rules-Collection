rule win_stealer_0x3401_auto {

    meta:
        id = "3dFD8rINOqrnnuaM8ZNCzA"
        fingerprint = "v1_sha256_00bd8b2b3e3b3733d5bcbc0fb6b2848b3225fb02bf487f9ea61c20713054d985"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.stealer_0x3401."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealer_0x3401"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 33c5 8945fc 53 56 57 33db bf01000000 }
            // n = 7, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   bf01000000           | mov                 edi, 1

        $sequence_1 = { 6800400000 8d85f07fffff c745fc00000000 6a00 }
            // n = 4, score = 100
            //   6800400000           | push                0x4000
            //   8d85f07fffff         | lea                 eax, [ebp - 0x8010]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   6a00                 | push                0

        $sequence_2 = { 898850030000 8b4508 59 c74048a8640210 8b4508 }
            // n = 5, score = 100
            //   898850030000         | mov                 dword ptr [eax + 0x350], ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   59                   | pop                 ecx
            //   c74048a8640210       | mov                 dword ptr [eax + 0x48], 0x100264a8
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_3 = { 83c40c c785acfdffff04010000 8d85acfdffff 50 8d85e8fdffff 50 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   c785acfdffff04010000     | mov    dword ptr [ebp - 0x254], 0x104
            //   8d85acfdffff         | lea                 eax, [ebp - 0x254]
            //   50                   | push                eax
            //   8d85e8fdffff         | lea                 eax, [ebp - 0x218]
            //   50                   | push                eax

        $sequence_4 = { c645fc0b 8d4da8 e8???????? 83c408 6aff c645fc0c }
            // n = 6, score = 100
            //   c645fc0b             | mov                 byte ptr [ebp - 4], 0xb
            //   8d4da8               | lea                 ecx, [ebp - 0x58]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6aff                 | push                -1
            //   c645fc0c             | mov                 byte ptr [ebp - 4], 0xc

        $sequence_5 = { 837c240800 75be ddd8 db2d???????? b802000000 833d????????00 0f8590190000 }
            // n = 7, score = 100
            //   837c240800           | cmp                 dword ptr [esp + 8], 0
            //   75be                 | jne                 0xffffffc0
            //   ddd8                 | fstp                st(0)
            //   db2d????????         |                     
            //   b802000000           | mov                 eax, 2
            //   833d????????00       |                     
            //   0f8590190000         | jne                 0x1996

        $sequence_6 = { 8d4c2434 e8???????? 53 e8???????? 83c404 8d44242c 8bcf }
            // n = 7, score = 100
            //   8d4c2434             | lea                 ecx, [esp + 0x34]
            //   e8????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d44242c             | lea                 eax, [esp + 0x2c]
            //   8bcf                 | mov                 ecx, edi

        $sequence_7 = { 50 6a00 66c745d90000 c645db00 660fd645e6 66c745ee0000 ffd7 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6a00                 | push                0
            //   66c745d90000         | mov                 word ptr [ebp - 0x27], 0
            //   c645db00             | mov                 byte ptr [ebp - 0x25], 0
            //   660fd645e6           | movq                qword ptr [ebp - 0x1a], xmm0
            //   66c745ee0000         | mov                 word ptr [ebp - 0x12], 0
            //   ffd7                 | call                edi

        $sequence_8 = { 50 8d45f4 64a300000000 8d8580fdffff c7857cfdffff00000000 50 ff15???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8d8580fdffff         | lea                 eax, [ebp - 0x280]
            //   c7857cfdffff00000000     | mov    dword ptr [ebp - 0x284], 0
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_9 = { f30f59c1 f30f110424 e8???????? f30f100d???????? 8b559c f20f5ac0 51 }
            // n = 7, score = 100
            //   f30f59c1             | mulss               xmm0, xmm1
            //   f30f110424           | movss               dword ptr [esp], xmm0
            //   e8????????           |                     
            //   f30f100d????????     |                     
            //   8b559c               | mov                 edx, dword ptr [ebp - 0x64]
            //   f20f5ac0             | cvtsd2ss            xmm0, xmm0
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 357376
}
