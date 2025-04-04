rule win_megacortex_auto {

    meta:
        id = "3NhPDmXVBap4XkhNOXVoeo"
        fingerprint = "v1_sha256_708d38e954539c490225999d6efcff9513f99a24765329194cd39e598c2360c1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.megacortex."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.megacortex"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 e8???????? 8bf0 83c40c 85f6 756e ff751c }
            // n = 7, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   85f6                 | test                esi, esi
            //   756e                 | jne                 0x70
            //   ff751c               | push                dword ptr [ebp + 0x1c]

        $sequence_1 = { 03c8 890a 8b55e8 5f 0f114204 66897214 5e }
            // n = 7, score = 400
            //   03c8                 | add                 ecx, eax
            //   890a                 | mov                 dword ptr [edx], ecx
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   5f                   | pop                 edi
            //   0f114204             | movups              xmmword ptr [edx + 4], xmm0
            //   66897214             | mov                 word ptr [edx + 0x14], si
            //   5e                   | pop                 esi

        $sequence_2 = { 8b75c8 8975dc 8d4aff f7d9 1bc9 23c1 03c2 }
            // n = 7, score = 400
            //   8b75c8               | mov                 esi, dword ptr [ebp - 0x38]
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   8d4aff               | lea                 ecx, [edx - 1]
            //   f7d9                 | neg                 ecx
            //   1bc9                 | sbb                 ecx, ecx
            //   23c1                 | and                 eax, ecx
            //   03c2                 | add                 eax, edx

        $sequence_3 = { 8985a8fbffff 85c0 0f845e020000 50 e8???????? 0fb6d8 0f57c0 }
            // n = 7, score = 400
            //   8985a8fbffff         | mov                 dword ptr [ebp - 0x458], eax
            //   85c0                 | test                eax, eax
            //   0f845e020000         | je                  0x264
            //   50                   | push                eax
            //   e8????????           |                     
            //   0fb6d8               | movzx               ebx, al
            //   0f57c0               | xorps               xmm0, xmm0

        $sequence_4 = { 8d46ff f7d8 1bc0 23c2 8bd7 03f0 8d7d0c }
            // n = 7, score = 400
            //   8d46ff               | lea                 eax, [esi - 1]
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   23c2                 | and                 eax, edx
            //   8bd7                 | mov                 edx, edi
            //   03f0                 | add                 esi, eax
            //   8d7d0c               | lea                 edi, [ebp + 0xc]

        $sequence_5 = { 23ca 03c1 8906 8b45d8 51 8bf4 8d4dd8 }
            // n = 7, score = 400
            //   23ca                 | and                 ecx, edx
            //   03c1                 | add                 eax, ecx
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   51                   | push                ecx
            //   8bf4                 | mov                 esi, esp
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]

        $sequence_6 = { 8b45f8 8d75e8 ff7508 51 8d50ff 8bfc 8d4df8 }
            // n = 7, score = 400
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8d75e8               | lea                 esi, [ebp - 0x18]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   8d50ff               | lea                 edx, [eax - 1]
            //   8bfc                 | mov                 edi, esp
            //   8d4df8               | lea                 ecx, [ebp - 8]

        $sequence_7 = { ff5004 8bf7 85ff 0f8562ffffff 8b4df4 64890d00000000 }
            // n = 6, score = 400
            //   ff5004               | call                dword ptr [eax + 4]
            //   8bf7                 | mov                 esi, edi
            //   85ff                 | test                edi, edi
            //   0f8562ffffff         | jne                 0xffffff68
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_8 = { f7d8 895dfc 1bc0 23c1 8b10 2bc6 83e2fd }
            // n = 7, score = 400
            //   f7d8                 | neg                 eax
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   1bc0                 | sbb                 eax, eax
            //   23c1                 | and                 eax, ecx
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   2bc6                 | sub                 eax, esi
            //   83e2fd               | and                 edx, 0xfffffffd

        $sequence_9 = { e8???????? 8d4598 c645fc05 50 8d45d8 83cb0a 50 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8d4598               | lea                 eax, [ebp - 0x68]
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   50                   | push                eax
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   83cb0a               | or                  ebx, 0xa
            //   50                   | push                eax

    condition:
        7 of them and filesize < 1556480
}
