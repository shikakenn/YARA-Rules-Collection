rule win_spectre_auto {

    meta:
        id = "1B7DPMauPhtnj1LIqnWoIa"
        fingerprint = "v1_sha256_fb8efa47f6cbb2730748ec520c0057da98d0d3b4bb855873b3521ccc59bde3f2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.spectre."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spectre"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 40 8945b0 894dac 3d00100000 7215 8d45b0 50 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   894dac               | mov                 dword ptr [ebp - 0x54], ecx
            //   3d00100000           | cmp                 eax, 0x1000
            //   7215                 | jb                  0x17
            //   8d45b0               | lea                 eax, [ebp - 0x50]
            //   50                   | push                eax

        $sequence_1 = { 8d8c243c010000 e8???????? 8b8c2454010000 5f 5e 5d 5b }
            // n = 7, score = 100
            //   8d8c243c010000       | lea                 ecx, [esp + 0x13c]
            //   e8????????           |                     
            //   8b8c2454010000       | mov                 ecx, dword ptr [esp + 0x154]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_2 = { 897110 897114 e8???????? e8???????? 83c418 83ec18 8bcc }
            // n = 7, score = 100
            //   897110               | mov                 dword ptr [ecx + 0x10], esi
            //   897114               | mov                 dword ptr [ecx + 0x14], esi
            //   e8????????           |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   83ec18               | sub                 esp, 0x18
            //   8bcc                 | mov                 ecx, esp

        $sequence_3 = { 8d45cc 57 ff7510 8b7d08 50 e8???????? 59 }
            // n = 7, score = 100
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   57                   | push                edi
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_4 = { 51 e8???????? 59 59 885c2410 8d8424a0000000 ff742410 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   885c2410             | mov                 byte ptr [esp + 0x10], bl
            //   8d8424a0000000       | lea                 eax, [esp + 0xa0]
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_5 = { 58 0fb60c8556424600 0fb6348557424600 8bf9 8985d8f6ffff c1e702 57 }
            // n = 7, score = 100
            //   58                   | pop                 eax
            //   0fb60c8556424600     | movzx               ecx, byte ptr [eax*4 + 0x464256]
            //   0fb6348557424600     | movzx               esi, byte ptr [eax*4 + 0x464257]
            //   8bf9                 | mov                 edi, ecx
            //   8985d8f6ffff         | mov                 dword ptr [ebp - 0x928], eax
            //   c1e702               | shl                 edi, 2
            //   57                   | push                edi

        $sequence_6 = { 8b30 ffd7 bb???????? 6685c0 0f85b0030000 b9a2000000 83fe6e }
            // n = 7, score = 100
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   ffd7                 | call                edi
            //   bb????????           |                     
            //   6685c0               | test                ax, ax
            //   0f85b0030000         | jne                 0x3b6
            //   b9a2000000           | mov                 ecx, 0xa2
            //   83fe6e               | cmp                 esi, 0x6e

        $sequence_7 = { 85ff 7425 8b442444 2bc3 50 53 }
            // n = 6, score = 100
            //   85ff                 | test                edi, edi
            //   7425                 | je                  0x27
            //   8b442444             | mov                 eax, dword ptr [esp + 0x44]
            //   2bc3                 | sub                 eax, ebx
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_8 = { 53 53 ff7584 ffd7 85c0 740c ff36 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   ff7584               | push                dword ptr [ebp - 0x7c]
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   740c                 | je                  0xe
            //   ff36                 | push                dword ptr [esi]

        $sequence_9 = { 3dffffff3f 7479 40 57 50 89442414 e8???????? }
            // n = 7, score = 100
            //   3dffffff3f           | cmp                 eax, 0x3fffffff
            //   7479                 | je                  0x7b
            //   40                   | inc                 eax
            //   57                   | push                edi
            //   50                   | push                eax
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 990208
}
