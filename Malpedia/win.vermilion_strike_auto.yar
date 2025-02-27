rule win_vermilion_strike_auto {

    meta:
        id = "1xhgRDK1PLj4hBA1sjJkDi"
        fingerprint = "v1_sha256_ffc8a6cd25f24a5bbb4ecf81a74aa2be97f9696d5656c7bc8cb3391d29c69c5d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.vermilion_strike."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vermilion_strike"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 03c1 a3???????? e9???????? 8b5608 42 52 e8???????? }
            // n = 7, score = 200
            //   03c1                 | add                 eax, ecx
            //   a3????????           |                     
            //   e9????????           |                     
            //   8b5608               | mov                 edx, dword ptr [esi + 8]
            //   42                   | inc                 edx
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_1 = { 8b6f04 eb03 8d6f04 8b15???????? 8b7f1c 6880ee3600 }
            // n = 6, score = 200
            //   8b6f04               | mov                 ebp, dword ptr [edi + 4]
            //   eb03                 | jmp                 5
            //   8d6f04               | lea                 ebp, [edi + 4]
            //   8b15????????         |                     
            //   8b7f1c               | mov                 edi, dword ptr [edi + 0x1c]
            //   6880ee3600           | push                0x36ee80

        $sequence_2 = { 68???????? c644241806 e8???????? 68???????? c644241807 e8???????? b8???????? }
            // n = 7, score = 200
            //   68????????           |                     
            //   c644241806           | mov                 byte ptr [esp + 0x18], 6
            //   e8????????           |                     
            //   68????????           |                     
            //   c644241807           | mov                 byte ptr [esp + 0x18], 7
            //   e8????????           |                     
            //   b8????????           |                     

        $sequence_3 = { 50 c744241001000000 e8???????? 8b8c24c4000000 8b9424c0000000 51 52 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   c744241001000000     | mov                 dword ptr [esp + 0x10], 1
            //   e8????????           |                     
            //   8b8c24c4000000       | mov                 ecx, dword ptr [esp + 0xc4]
            //   8b9424c0000000       | mov                 edx, dword ptr [esp + 0xc0]
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_4 = { 2bf8 8b4c2418 57 8db424fc000000 8d942418010000 e8???????? }
            // n = 6, score = 200
            //   2bf8                 | sub                 edi, eax
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   57                   | push                edi
            //   8db424fc000000       | lea                 esi, [esp + 0xfc]
            //   8d942418010000       | lea                 edx, [esp + 0x118]
            //   e8????????           |                     

        $sequence_5 = { 83c508 55 e8???????? 83c404 55 8bf0 6a00 }
            // n = 7, score = 200
            //   83c508               | add                 ebp, 8
            //   55                   | push                ebp
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   55                   | push                ebp
            //   8bf0                 | mov                 esi, eax
            //   6a00                 | push                0

        $sequence_6 = { 50 56 eb06 53 68???????? 8d442454 e8???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   56                   | push                esi
            //   eb06                 | jmp                 8
            //   53                   | push                ebx
            //   68????????           |                     
            //   8d442454             | lea                 eax, [esp + 0x54]
            //   e8????????           |                     

        $sequence_7 = { 53 e8???????? 83c404 8d742e08 eb7d 0fb64c3704 0fb6543705 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d742e08             | lea                 esi, [esi + ebp + 8]
            //   eb7d                 | jmp                 0x7f
            //   0fb64c3704           | movzx               ecx, byte ptr [edi + esi + 4]
            //   0fb6543705           | movzx               edx, byte ptr [edi + esi + 5]

        $sequence_8 = { 8b442420 8b7c2424 3bfb 7544 8b542428 8b5e14 }
            // n = 6, score = 200
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8b7c2424             | mov                 edi, dword ptr [esp + 0x24]
            //   3bfb                 | cmp                 edi, ebx
            //   7544                 | jne                 0x46
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
            //   8b5e14               | mov                 ebx, dword ptr [esi + 0x14]

        $sequence_9 = { 750c c705????????01000000 eba9 83f808 75a4 c705????????04000000 eb98 }
            // n = 7, score = 200
            //   750c                 | jne                 0xe
            //   c705????????01000000     |     
            //   eba9                 | jmp                 0xffffffab
            //   83f808               | cmp                 eax, 8
            //   75a4                 | jne                 0xffffffa6
            //   c705????????04000000     |     
            //   eb98                 | jmp                 0xffffff9a

    condition:
        7 of them and filesize < 540672
}
