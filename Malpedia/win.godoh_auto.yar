rule win_godoh_auto {

    meta:
        id = "7K8OTvoxv7U0M0DYeu0kvZ"
        fingerprint = "v1_sha256_7b82452017b3433a23ca27d45dcd957705f4360adcb00cbd3f330e91cdc74dcc"
        version = "1"
        date = "2020-10-14"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.godoh"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { cf 8e5ff8 88ee e8???????? 4550 }
            // n = 5, score = 100
            //   cf                   | jecxz               0x31
            //   8e5ff8               | test                dword ptr [esi], ebp
            //   88ee                 | mov                 edx, 0x79289db6
            //   e8????????           |                     
            //   4550                 | ret                 0x310b

        $sequence_1 = { 4889e9 ff15???????? 4809c0 7409 488903 4883c308 ebd6 }
            // n = 7, score = 100
            //   4889e9               | jmp                 0x30
            //   ff15????????         |                     
            //   4809c0               | add                 ebx, ebx
            //   7409                 | jne                 0x2e
            //   488903               | mov                 ebx, dword ptr [esi]
            //   4883c308             | dec                 eax
            //   ebd6                 | sub                 esi, -4

        $sequence_2 = { 11c0 01db 750a 8b1e 4883eefc 11db }
            // n = 6, score = 100
            //   11c0                 | rcl                 cl, cl
            //   01db                 | or                  byte ptr [ecx - 0x75], cl
            //   750a                 | adc                 al, 0xd1
            //   8b1e                 | or                  ecx, dword ptr [edi - 0x595d3efa]
            //   4883eefc             | sal                 ebx, 1
            //   11db                 | dec                 edx

        $sequence_3 = { 36b6f8 188723d198a8 5d 55 8799b90f0f4a }
            // n = 5, score = 100
            //   36b6f8               | and                 eax, 0x538c5841
            //   188723d198a8         | sub                 byte ptr [0xf2a6e9c9], ah
            //   5d                   | outsb               dx, byte ptr [esi]
            //   55                   | adc                 al, dh
            //   8799b90f0f4a         | outsd               dx, dword ptr [esi]

        $sequence_4 = { 3541364137 41384139 41129420fe3a413b 413c41 3dfe03897f }
            // n = 5, score = 100
            //   3541364137           | and                 byte ptr [ebp + 0x2a], dh
            //   41384139             | xor                 dword ptr [edi], ebx
            //   41129420fe3a413b     | and                 eax, 0x80ec7da7
            //   413c41               | test                byte ptr [edx], al
            //   3dfe03897f           | jae                 0xf

        $sequence_5 = { 7013 d34017 7b00 5c 35483f80e2 }
            // n = 5, score = 100
            //   7013                 | inc                 ebp
            //   d34017               | or                  bh, al
            //   7b00                 | xchg                eax, esi
            //   5c                   | push                0x80ea014a
            //   35483f80e2           | cli                 

        $sequence_6 = { 2825c9e9a6f2 6e 12c6 6f e139 f011402e }
            // n = 6, score = 100
            //   2825c9e9a6f2         | cmp                 ebp, edi
            //   6e                   | and                 eax, 0x1c36cd08
            //   12c6                 | or                  eax, 0x6bd1e2ed
            //   6f                   | push                esp
            //   e139                 | xor                 byte ptr [eax + 0x21], 0xc5
            //   f011402e             | and                 dword ptr [esi + 0x44047b32], ecx

        $sequence_7 = { d02489 9e f2096a14 7952 5a b8b601c765 }
            // n = 6, score = 100
            //   d02489               | add                 dh, ah
            //   9e                   | pop                 esi
            //   f2096a14             | mov                 ecx, 0x4effffff
            //   7952                 | stc                 
            //   5a                   | cli                 
            //   b8b601c765           | cmp                 eax, 0x39fb1996

        $sequence_8 = { 852e bab69d2879 438b9c760a594a07 bd0e531786 }
            // n = 4, score = 100
            //   852e                 | imul                byte ptr [0xd91e87e3]
            //   bab69d2879           | and                 dword ptr [eax], 0x45cc2633
            //   438b9c760a594a07     | or                  byte ptr [ebx], bh
            //   bd0e531786           | push                ecx

        $sequence_9 = { 35dc3e6904 793c 5f 6ad5 }
            // n = 4, score = 100
            //   35dc3e6904           | cmp                 dl, ch
            //   793c                 | xor                 bh, byte ptr [edi]
            //   5f                   | leave               
            //   6ad5                 | jo                  0xfffffffd

    condition:
        7 of them and filesize < 14467072
}
