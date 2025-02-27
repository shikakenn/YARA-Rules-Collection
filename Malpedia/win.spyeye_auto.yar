rule win_spyeye_auto {

    meta:
        id = "5fiG66Ku4ZAEXyw0bz7f0a"
        fingerprint = "v1_sha256_f4149a2d0558cdca789e55a3da096c9eb02a06e0cbb6c5f6412ffac38db590ec"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.spyeye."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spyeye"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 81fbffffff7f 7509 56 57 e8???????? 8bd8 3bde }
            // n = 7, score = 700
            //   81fbffffff7f         | cmp                 ebx, 0x7fffffff
            //   7509                 | jne                 0xb
            //   56                   | push                esi
            //   57                   | push                edi
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   3bde                 | cmp                 ebx, esi

        $sequence_1 = { 740e 8965fc ff750c ff7508 ffd0 8b65fc c9 }
            // n = 7, score = 700
            //   740e                 | je                  0x10
            //   8965fc               | mov                 dword ptr [ebp - 4], esp
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd0                 | call                eax
            //   8b65fc               | mov                 esp, dword ptr [ebp - 4]
            //   c9                   | leave               

        $sequence_2 = { 751b 57 6800000002 6a03 }
            // n = 4, score = 700
            //   751b                 | jne                 0x1d
            //   57                   | push                edi
            //   6800000002           | push                0x2000000
            //   6a03                 | push                3

        $sequence_3 = { 7414 8965fc ff7514 ff7510 }
            // n = 4, score = 700
            //   7414                 | je                  0x16
            //   8965fc               | mov                 dword ptr [ebp - 4], esp
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_4 = { 50 57 e8???????? 8b5d14 33f6 3bde }
            // n = 6, score = 700
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b5d14               | mov                 ebx, dword ptr [ebp + 0x14]
            //   33f6                 | xor                 esi, esi
            //   3bde                 | cmp                 ebx, esi

        $sequence_5 = { 53 56 57 33ff 57 be80000000 56 }
            // n = 7, score = 700
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   57                   | push                edi
            //   be80000000           | mov                 esi, 0x80
            //   56                   | push                esi

        $sequence_6 = { 56 57 e8???????? 57 8bf0 e8???????? 8bc6 }
            // n = 7, score = 700
            //   56                   | push                esi
            //   57                   | push                edi
            //   e8????????           |                     
            //   57                   | push                edi
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_7 = { 6a03 57 6a01 56 ff750c }
            // n = 5, score = 700
            //   6a03                 | push                3
            //   57                   | push                edi
            //   6a01                 | push                1
            //   56                   | push                esi
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_8 = { 740e 837dfcff 7408 ff75fc e8???????? 3bdf }
            // n = 6, score = 700
            //   740e                 | je                  0x10
            //   837dfcff             | cmp                 dword ptr [ebp - 4], -1
            //   7408                 | je                  0xa
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   3bdf                 | cmp                 ebx, edi

        $sequence_9 = { 55 8bec 51 68b787554d }
            // n = 4, score = 700
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   68b787554d           | push                0x4d5587b7

    condition:
        7 of them and filesize < 741376
}
