rule win_mariposa_auto {

    meta:
        id = "UuCJmHEyBJllkjMJhh9EC"
        fingerprint = "v1_sha256_343ac33f57cd9cc9bfc1841bf1bd211734de245f417ee554220587a46ed4086f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mariposa."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mariposa"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 55 8bec 53 56 bb???????? 43 }
            // n = 6, score = 600
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   56                   | push                esi
            //   bb????????           |                     
            //   43                   | inc                 ebx

        $sequence_1 = { ffd3 33c0 50 e8???????? 33c0 }
            // n = 5, score = 600
            //   ffd3                 | call                ebx
            //   33c0                 | xor                 eax, eax
            //   50                   | push                eax
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 53 56 bb???????? 43 }
            // n = 4, score = 600
            //   53                   | push                ebx
            //   56                   | push                esi
            //   bb????????           |                     
            //   43                   | inc                 ebx

        $sequence_3 = { 885c0cff e2f1 ba???????? 2bd6 8bdc 03da 4b }
            // n = 7, score = 600
            //   885c0cff             | mov                 byte ptr [esp + ecx - 1], bl
            //   e2f1                 | loop                0xfffffff3
            //   ba????????           |                     
            //   2bd6                 | sub                 edx, esi
            //   8bdc                 | mov                 ebx, esp
            //   03da                 | add                 ebx, edx
            //   4b                   | dec                 ebx

        $sequence_4 = { 8a1c0e 02d8 32dc fec0 885c0cff e2f1 }
            // n = 6, score = 600
            //   8a1c0e               | mov                 bl, byte ptr [esi + ecx]
            //   02d8                 | add                 bl, al
            //   32dc                 | xor                 bl, ah
            //   fec0                 | inc                 al
            //   885c0cff             | mov                 byte ptr [esp + ecx - 1], bl
            //   e2f1                 | loop                0xfffffff3

        $sequence_5 = { 8bdc 03da 4b 54 ffd3 33c0 }
            // n = 6, score = 600
            //   8bdc                 | mov                 ebx, esp
            //   03da                 | add                 ebx, edx
            //   4b                   | dec                 ebx
            //   54                   | push                esp
            //   ffd3                 | call                ebx
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 885c0cff e2f1 ba???????? 2bd6 }
            // n = 4, score = 600
            //   885c0cff             | mov                 byte ptr [esp + ecx - 1], bl
            //   e2f1                 | loop                0xfffffff3
            //   ba????????           |                     
            //   2bd6                 | sub                 edx, esi

        $sequence_7 = { 8a4301 8a6302 f6d0 02c4 d0f8 8a1c0e }
            // n = 6, score = 600
            //   8a4301               | mov                 al, byte ptr [ebx + 1]
            //   8a6302               | mov                 ah, byte ptr [ebx + 2]
            //   f6d0                 | not                 al
            //   02c4                 | add                 al, ah
            //   d0f8                 | sar                 al, 1
            //   8a1c0e               | mov                 bl, byte ptr [esi + ecx]

        $sequence_8 = { 53 56 bb???????? 43 803b00 }
            // n = 5, score = 600
            //   53                   | push                ebx
            //   56                   | push                esi
            //   bb????????           |                     
            //   43                   | inc                 ebx
            //   803b00               | cmp                 byte ptr [ebx], 0

        $sequence_9 = { 03da 4b 54 ffd3 33c0 }
            // n = 5, score = 600
            //   03da                 | add                 ebx, edx
            //   4b                   | dec                 ebx
            //   54                   | push                esp
            //   ffd3                 | call                ebx
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 311296
}
