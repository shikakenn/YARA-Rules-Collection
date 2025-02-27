rule win_metamorfo_auto {

    meta:
        id = "1fg1aQYm9CGoPmRZREn9JQ"
        fingerprint = "v1_sha256_7351b6774be36e0094249ee11c1c5baca5cad5794746ad4bfc3f2faa2c1cbd52"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.metamorfo"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8945ec 8b45fc 8b4044 0345ec 8b55fc 8b5254 8d0482 }
            // n = 7, score = 100
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4044               | mov                 eax, dword ptr [eax + 0x44]
            //   0345ec               | add                 eax, dword ptr [ebp - 0x14]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b5254               | mov                 edx, dword ptr [edx + 0x54]
            //   8d0482               | lea                 eax, [edx + eax*4]

        $sequence_1 = { e8???????? 68837f0000 8b45dc 50 e8???????? 68847f0000 8b45d8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   68837f0000           | push                0x7f83
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   e8????????           |                     
            //   68847f0000           | push                0x7f84
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]

        $sequence_2 = { c78688000000ffffffff c7868c000000ffffffff 33c0 898698000000 33c0 8986a0000000 33c0 }
            // n = 7, score = 100
            //   c78688000000ffffffff     | mov    dword ptr [esi + 0x88], 0xffffffff
            //   c7868c000000ffffffff     | mov    dword ptr [esi + 0x8c], 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   898698000000         | mov                 dword ptr [esi + 0x98], eax
            //   33c0                 | xor                 eax, eax
            //   8986a0000000         | mov                 dword ptr [esi + 0xa0], eax
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { d918 9b 8b45f8 d9e8 d86804 8b45f8 d95804 }
            // n = 7, score = 100
            //   d918                 | fstp                dword ptr [eax]
            //   9b                   | wait                
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   d9e8                 | fld1                
            //   d86804               | fsubr               dword ptr [eax + 4]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   d95804               | fstp                dword ptr [eax + 4]

        $sequence_4 = { c1ea08 8b45b0 8810 47 43 4e 0f8561ffffff }
            // n = 7, score = 100
            //   c1ea08               | shr                 edx, 8
            //   8b45b0               | mov                 eax, dword ptr [ebp - 0x50]
            //   8810                 | mov                 byte ptr [eax], dl
            //   47                   | inc                 edi
            //   43                   | inc                 ebx
            //   4e                   | dec                 esi
            //   0f8561ffffff         | jne                 0xffffff67

        $sequence_5 = { e8???????? 84c0 7406 8bb7a4020000 8bc6 5f 5e }
            // n = 7, score = 100
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7406                 | je                  8
            //   8bb7a4020000         | mov                 esi, dword ptr [edi + 0x2a4]
            //   8bc6                 | mov                 eax, esi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_6 = { e8???????? 0fb64014 2c01 720d fec8 0f84d6010000 e9???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   0fb64014             | movzx               eax, byte ptr [eax + 0x14]
            //   2c01                 | sub                 al, 1
            //   720d                 | jb                  0xf
            //   fec8                 | dec                 al
            //   0f84d6010000         | je                  0x1dc
            //   e9????????           |                     

        $sequence_7 = { a3???????? 8b45f8 e8???????? b8???????? e8???????? b8???????? e8???????? }
            // n = 7, score = 100
            //   a3????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   b8????????           |                     
            //   e8????????           |                     
            //   b8????????           |                     
            //   e8????????           |                     

        $sequence_8 = { ffb540faffff 68???????? ff35???????? 68???????? ff35???????? 68???????? 8d8550faffff }
            // n = 7, score = 100
            //   ffb540faffff         | push                dword ptr [ebp - 0x5c0]
            //   68????????           |                     
            //   ff35????????         |                     
            //   68????????           |                     
            //   ff35????????         |                     
            //   68????????           |                     
            //   8d8550faffff         | lea                 eax, [ebp - 0x5b0]

        $sequence_9 = { ff5230 48 8945ec 8bc3 8b10 ff5224 8b55b4 }
            // n = 7, score = 100
            //   ff5230               | call                dword ptr [edx + 0x30]
            //   48                   | dec                 eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8bc3                 | mov                 eax, ebx
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff5224               | call                dword ptr [edx + 0x24]
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]

    condition:
        7 of them and filesize < 20349952
}
