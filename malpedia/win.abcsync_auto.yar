rule win_abcsync_auto {

    meta:
        id = "7YkmkLjFCchdFm6oWdobVj"
        fingerprint = "v1_sha256_02ae937251ee063be53e02e33e98dc9b276f9fd2074f9431e5bc0ede2973fadf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.abcsync."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.abcsync"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6bc232 2bc8 8d4107 410fb64c1afc 4898 }
            // n = 5, score = 100
            //   6bc232               | sub                 eax, edi
            //   2bc8                 | dec                 esp
            //   8d4107               | mov                 dword ptr [esp + 0x20], esp
            //   410fb64c1afc         | dec                 eax
            //   4898                 | add                 edx, ebx

        $sequence_1 = { 41884afc 418d4916 f7e9 418bc9 c1fa04 8bc2 c1e81f }
            // n = 7, score = 100
            //   41884afc             | dec                 eax
            //   418d4916             | lea                 edx, [0xa908]
            //   f7e9                 | dec                 eax
            //   418bc9               | test                eax, eax
            //   c1fa04               | je                  0x11e5
            //   8bc2                 | dec                 eax
            //   c1e81f               | mov                 ecx, ebx

        $sequence_2 = { 6bc232 2bc8 8d4121 4898 420fb60c18 }
            // n = 5, score = 100
            //   6bc232               | mov                 dword ptr [esp + 0x28], ebx
            //   2bc8                 | inc                 esp
            //   8d4121               | mov                 esi, dword ptr [esp + 0x54]
            //   4898                 | inc                 ebp
            //   420fb60c18           | test                esi, esi

        $sequence_3 = { c744243442015500 c744243847013200 c744243c4d004d00 c74424404e000100 e8???????? 488bc8 ff15???????? }
            // n = 7, score = 100
            //   c744243442015500     | imul                ecx
            //   c744243847013200     | inc                 edx
            //   c744243c4d004d00     | movzx               ecx, byte ptr [ebx + edx + 2]
            //   c74424404e000100     | dec                 eax
            //   e8????????           |                     
            //   488bc8               | cwde                
            //   ff15????????         |                     

        $sequence_4 = { 418bc9 4d8d521f c1fa04 8bc2 c1e81f 03d0 6bc232 }
            // n = 7, score = 100
            //   418bc9               | dec                 eax
            //   4d8d521f             | and                 dword ptr [esp + 0x80], 0
            //   c1fa04               | inc                 ebp
            //   8bc2                 | test                dh, dh
            //   c1e81f               | je                  0x1801
            //   03d0                 | dec                 eax
            //   6bc232               | lea                 edi, [0x10cdf]

        $sequence_5 = { e8???????? 488d15ba940000 488d0dab940000 e8???????? 488b4308 833800 750e }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d15ba940000       | inc                 cx
            //   488d0dab940000       | mov                 dword ptr [edx + 0x40], eax
            //   e8????????           |                     
            //   488b4308             | mov                 eax, 0x51eb851f
            //   833800               | imul                ecx
            //   750e                 | inc                 ecx

        $sequence_6 = { 2bc8 8d4112 410fb64c1afe 4898 422a0c18 41884afe 4183f913 }
            // n = 7, score = 100
            //   2bc8                 | dec                 eax
            //   8d4112               | mov                 dword ptr [esp + 0x30], eax
            //   410fb64c1afe         | dec                 eax
            //   4898                 | lea                 ecx, [esp + 0x20]
            //   422a0c18             | mov                 dword ptr [esp + 0x20], 0x77705d66
            //   41884afe             | mov                 dword ptr [esp + 0x24], 0x333c7060
            //   4183f913             | dec                 eax

        $sequence_7 = { 4c89442420 33c9 4533c0 ff15???????? 85c0 0f8e37040000 488b05???????? }
            // n = 7, score = 100
            //   4c89442420           | nop                 word ptr [eax + eax]
            //   33c9                 | dec                 esp
            //   4533c0               | mov                 esi, dword ptr [esp + 0x3e0]
            //   ff15????????         |                     
            //   85c0                 | dec                 eax
            //   0f8e37040000         | mov                 edi, dword ptr [esp + 0x3f0]
            //   488b05????????       |                     

        $sequence_8 = { 4903ce 85db 742a 4d8bc5 4c2bc1 0f1f4000 6666660f1f840000000000 }
            // n = 7, score = 100
            //   4903ce               | inc                 edx
            //   85db                 | cmp                 byte ptr [ecx + edi*8 + 0x38], bl
            //   742a                 | jge                 0x1275
            //   4d8bc5               | mov                 ecx, esi
            //   4c2bc1               | dec                 eax
            //   0f1f4000             | lea                 eax, [0x15a95]
            //   6666660f1f840000000000     | ret    

        $sequence_9 = { 8bc2 c1e81f 03d0 6bc232 2bc8 8d411c 410fb64c1afc }
            // n = 7, score = 100
            //   8bc2                 | mov                 eax, 0x51eb851f
            //   c1e81f               | inc                 ecx
            //   03d0                 | mov                 byte ptr [edx - 4], cl
            //   6bc232               | inc                 ecx
            //   2bc8                 | lea                 ecx, [ecx + 0x1d]
            //   8d411c               | imul                ecx
            //   410fb64c1afc         | inc                 ecx

    condition:
        7 of them and filesize < 348160
}
