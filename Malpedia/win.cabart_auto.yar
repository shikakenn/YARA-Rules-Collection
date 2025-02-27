rule win_cabart_auto {

    meta:
        id = "75B5PQSJKw6zYddt9MYK71"
        fingerprint = "v1_sha256_4c41cdb81a5db228073171586c9e5e6d6ecfd715a748c36291a1859ea7ac8fe5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cabart."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cabart"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6804010000 50 ff15???????? 83c410 6a10 68???????? 8d85fcfeffff }
            // n = 7, score = 300
            //   6804010000           | push                0x104
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10
            //   6a10                 | push                0x10
            //   68????????           |                     
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]

        $sequence_1 = { 85d2 7ff4 eb01 42 2bca }
            // n = 5, score = 300
            //   85d2                 | test                edx, edx
            //   7ff4                 | jg                  0xfffffff6
            //   eb01                 | jmp                 3
            //   42                   | inc                 edx
            //   2bca                 | sub                 ecx, edx

        $sequence_2 = { 83c420 ff7508 ffd6 8bf8 }
            // n = 4, score = 300
            //   83c420               | add                 esp, 0x20
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd6                 | call                esi
            //   8bf8                 | mov                 edi, eax

        $sequence_3 = { 8975fc 5f 395d10 740e 57 }
            // n = 5, score = 300
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   5f                   | pop                 edi
            //   395d10               | cmp                 dword ptr [ebp + 0x10], ebx
            //   740e                 | je                  0x10
            //   57                   | push                edi

        $sequence_4 = { 7d0a 686c090000 e8???????? 8b0f }
            // n = 4, score = 300
            //   7d0a                 | jge                 0xc
            //   686c090000           | push                0x96c
            //   e8????????           |                     
            //   8b0f                 | mov                 ecx, dword ptr [edi]

        $sequence_5 = { 7ff4 eb01 42 2bca }
            // n = 4, score = 300
            //   7ff4                 | jg                  0xfffffff6
            //   eb01                 | jmp                 3
            //   42                   | inc                 edx
            //   2bca                 | sub                 ecx, edx

        $sequence_6 = { 6a50 5e 53 53 53 }
            // n = 5, score = 300
            //   6a50                 | push                0x50
            //   5e                   | pop                 esi
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_7 = { 8bd8 ff15???????? 3bdf 5b }
            // n = 4, score = 300
            //   8bd8                 | mov                 ebx, eax
            //   ff15????????         |                     
            //   3bdf                 | cmp                 ebx, edi
            //   5b                   | pop                 ebx

        $sequence_8 = { ff750c ff7508 56 ff15???????? 56 8bd8 }
            // n = 6, score = 300
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   8bd8                 | mov                 ebx, eax

        $sequence_9 = { 68bb0b0000 ebe2 85ff 7507 68bc0b0000 ebd7 }
            // n = 6, score = 300
            //   68bb0b0000           | push                0xbbb
            //   ebe2                 | jmp                 0xffffffe4
            //   85ff                 | test                edi, edi
            //   7507                 | jne                 9
            //   68bc0b0000           | push                0xbbc
            //   ebd7                 | jmp                 0xffffffd9

    condition:
        7 of them and filesize < 32768
}
