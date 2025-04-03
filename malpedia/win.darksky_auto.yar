rule win_darksky_auto {

    meta:
        id = "3N8FCNf0MduefY5VGAKFeV"
        fingerprint = "v1_sha256_cc096bc519acb441baa3b128eca454a5c80e290fcd20694638d5f71f7e9e65b0"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darksky"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85c0 745c c745e001000000 8d45e4 50 8b45f8 e8???????? }
            // n = 7, score = 400
            //   85c0                 | test                eax, eax
            //   745c                 | je                  0x5e
            //   c745e001000000       | mov                 dword ptr [ebp - 0x20], 1
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     

        $sequence_1 = { 53 8955f8 8845ff 8b45f8 e8???????? 33c0 55 }
            // n = 7, score = 400
            //   53                   | push                ebx
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   55                   | push                ebp

        $sequence_2 = { 8b55f8 e8???????? 8b45fc e8???????? 8bd0 8bc3 }
            // n = 6, score = 400
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8bc3                 | mov                 eax, ebx

        $sequence_3 = { 6a00 e8???????? 807dff00 7409 c745ec02000000 }
            // n = 5, score = 400
            //   6a00                 | push                0
            //   e8????????           |                     
            //   807dff00             | cmp                 byte ptr [ebp - 1], 0
            //   7409                 | je                  0xb
            //   c745ec02000000       | mov                 dword ptr [ebp - 0x14], 2

        $sequence_4 = { 648920 6a00 6a00 8d45f8 50 8d45fc 50 }
            // n = 7, score = 400
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax

        $sequence_5 = { 8bf8 8bc7 e8???????? 8bf0 8bc5 8bd6 e8???????? }
            // n = 7, score = 400
            //   8bf8                 | mov                 edi, eax
            //   8bc7                 | mov                 eax, edi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8bc5                 | mov                 eax, ebp
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     

        $sequence_6 = { 33db 895df0 894df4 8955f8 8945fc 8b7508 8b45fc }
            // n = 7, score = 400
            //   33db                 | xor                 ebx, ebx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { e8???????? 50 ffd6 c605????????01 53 e8???????? a0???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   c605????????01       |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   a0????????           |                     

        $sequence_8 = { ffd6 c605????????01 53 e8???????? a0???????? }
            // n = 5, score = 400
            //   ffd6                 | call                esi
            //   c605????????01       |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   a0????????           |                     

        $sequence_9 = { 740d 68???????? e8???????? 50 }
            // n = 4, score = 400
            //   740d                 | je                  0xf
            //   68????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 827392
}
