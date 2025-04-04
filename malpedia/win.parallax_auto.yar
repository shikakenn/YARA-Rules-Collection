rule win_parallax_auto {

    meta:
        id = "3WvrbMkz2Wx7sqbI1snh9r"
        fingerprint = "v1_sha256_598728667b89c1a79c35abfecdd8c0a41fda3612c3bf2021240a756e9bc3373e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.parallax."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parallax"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 837e3000 740c 8b5630 8d424c 50 e8???????? e9???????? }
            // n = 7, score = 200
            //   837e3000             | cmp                 dword ptr [esi + 0x30], 0
            //   740c                 | je                  0xe
            //   8b5630               | mov                 edx, dword ptr [esi + 0x30]
            //   8d424c               | lea                 eax, [edx + 0x4c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_1 = { 6a00 ff35???????? ff5260 837f3400 7413 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   ff5260               | call                dword ptr [edx + 0x60]
            //   837f3400             | cmp                 dword ptr [edi + 0x34], 0
            //   7413                 | je                  0x15

        $sequence_2 = { 56 ff7508 e8???????? eb5e 3de9030000 7557 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   eb5e                 | jmp                 0x60
            //   3de9030000           | cmp                 eax, 0x3e9
            //   7557                 | jne                 0x59

        $sequence_3 = { 50 8d45f8 50 ff75fc ff96a4000000 85c0 0f850a010000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff96a4000000         | call                dword ptr [esi + 0xa4]
            //   85c0                 | test                eax, eax
            //   0f850a010000         | jne                 0x110

        $sequence_4 = { e8???????? 96 5f 5e 5d c20400 55 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   96                   | xchg                eax, esi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   55                   | push                ebp

        $sequence_5 = { c7474000200000 eb18 ff7640 8f45fc 8b35???????? 8b55fc }
            // n = 6, score = 200
            //   c7474000200000       | mov                 dword ptr [edi + 0x40], 0x2000
            //   eb18                 | jmp                 0x1a
            //   ff7640               | push                dword ptr [esi + 0x40]
            //   8f45fc               | pop                 dword ptr [ebp - 4]
            //   8b35????????         |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_6 = { 3b35???????? 72d0 58 8b1d???????? 6bdb04 03c3 8b7d0c }
            // n = 7, score = 200
            //   3b35????????         |                     
            //   72d0                 | jb                  0xffffffd2
            //   58                   | pop                 eax
            //   8b1d????????         |                     
            //   6bdb04               | imul                ebx, ebx, 4
            //   03c3                 | add                 eax, ebx
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]

        $sequence_7 = { 7530 6a01 68ff1f0000 e8???????? }
            // n = 4, score = 200
            //   7530                 | jne                 0x32
            //   6a01                 | push                1
            //   68ff1f0000           | push                0x1fff
            //   e8????????           |                     

        $sequence_8 = { 8975e4 8d55f0 8b0e 890a }
            // n = 4, score = 200
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   890a                 | mov                 dword ptr [edx], ecx

        $sequence_9 = { c7421c00000000 6a06 ff750c e8???????? }
            // n = 4, score = 200
            //   c7421c00000000       | mov                 dword ptr [edx + 0x1c], 0
            //   6a06                 | push                6
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 352256
}
