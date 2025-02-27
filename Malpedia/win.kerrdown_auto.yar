rule win_kerrdown_auto {

    meta:
        id = "7Qib7PgVFdU797VPexwbs5"
        fingerprint = "v1_sha256_5c1e70ce1c83c058010acdca1cced0163370ed7a63b1ae0a7c0e9df6e4e225f4"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.kerrdown."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kerrdown"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0f83a2000000 c64405e800 40 83f804 }
            // n = 4, score = 200
            //   0f83a2000000         | jae                 0xa8
            //   c64405e800           | mov                 byte ptr [ebp + eax - 0x18], 0
            //   40                   | inc                 eax
            //   83f804               | cmp                 eax, 4

        $sequence_1 = { 64a300000000 8bf9 897ddc c745d800000000 }
            // n = 4, score = 200
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf9                 | mov                 edi, ecx
            //   897ddc               | mov                 dword ptr [ebp - 0x24], edi
            //   c745d800000000       | mov                 dword ptr [ebp - 0x28], 0

        $sequence_2 = { b8???????? 5f 5d c20800 85f6 75b2 }
            // n = 6, score = 200
            //   b8????????           |                     
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   85f6                 | test                esi, esi
            //   75b2                 | jne                 0xffffffb4

        $sequence_3 = { b9???????? 2bc2 50 68???????? e8???????? 5f 5d }
            // n = 7, score = 200
            //   b9????????           |                     
            //   2bc2                 | sub                 eax, edx
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp

        $sequence_4 = { 6800080000 8bf0 e8???????? 8bd8 83c408 }
            // n = 5, score = 200
            //   6800080000           | push                0x800
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83c408               | add                 esp, 8

        $sequence_5 = { 897710 7202 8b0f c60100 b9???????? }
            // n = 5, score = 200
            //   897710               | mov                 dword ptr [edi + 0x10], esi
            //   7202                 | jb                  4
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   c60100               | mov                 byte ptr [ecx], 0
            //   b9????????           |                     

        $sequence_6 = { 897ddc c745d800000000 33f6 c747140f000000 b8cd220000 837f1410 }
            // n = 6, score = 200
            //   897ddc               | mov                 dword ptr [ebp - 0x24], edi
            //   c745d800000000       | mov                 dword ptr [ebp - 0x28], 0
            //   33f6                 | xor                 esi, esi
            //   c747140f000000       | mov                 dword ptr [edi + 0x14], 0xf
            //   b8cd220000           | mov                 eax, 0x22cd
            //   837f1410             | cmp                 dword ptr [edi + 0x14], 0x10

        $sequence_7 = { b8???????? 8b15???????? 57 8b3d???????? 83ff10 0f43c1 3d???????? }
            // n = 7, score = 200
            //   b8????????           |                     
            //   8b15????????         |                     
            //   57                   | push                edi
            //   8b3d????????         |                     
            //   83ff10               | cmp                 edi, 0x10
            //   0f43c1               | cmovae              eax, ecx
            //   3d????????           |                     

        $sequence_8 = { a1???????? 33c4 8944241c 6807800000 ff15???????? }
            // n = 5, score = 200
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   6807800000           | push                0x8007
            //   ff15????????         |                     

        $sequence_9 = { c745f800000000 83feff 7438 6a00 8d45f8 }
            // n = 5, score = 200
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   83feff               | cmp                 esi, -1
            //   7438                 | je                  0x3a
            //   6a00                 | push                0
            //   8d45f8               | lea                 eax, [ebp - 8]

    condition:
        7 of them and filesize < 278528
}
