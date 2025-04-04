rule win_ismdoor_auto {

    meta:
        id = "39tJrb4PhFJERIToWbILSz"
        fingerprint = "v1_sha256_b2a8beb2bbf9a7e436997cbc54636f7d3af94cae5a6618f143e6a6f5f28950e2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ismdoor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ismdoor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83f8ff 7504 32c0 eb05 c0e804 2401 84c0 }
            // n = 7, score = 400
            //   83f8ff               | cmp                 eax, -1
            //   7504                 | jne                 6
            //   32c0                 | xor                 al, al
            //   eb05                 | jmp                 7
            //   c0e804               | shr                 al, 4
            //   2401                 | and                 al, 1
            //   84c0                 | test                al, al

        $sequence_1 = { 488b15???????? e8???????? 488b3d???????? 488d5fe0 }
            // n = 4, score = 300
            //   488b15????????       |                     
            //   e8????????           |                     
            //   488b3d????????       |                     
            //   488d5fe0             | dec                 eax

        $sequence_2 = { 747e 4883f8ff 7606 4883c9ff }
            // n = 4, score = 300
            //   747e                 | mov                 edi, ebx
            //   4883f8ff             | dec                 eax
            //   7606                 | mov                 ebx, esi
            //   4883c9ff             | dec                 eax

        $sequence_3 = { 4889450f 48837e1808 7205 488b16 }
            // n = 4, score = 300
            //   4889450f             | cmp                 eax, -1
            //   48837e1808           | jbe                 0xc
            //   7205                 | dec                 eax
            //   488b16               | or                  ecx, 0xffffffff

        $sequence_4 = { 8bce 83e11f 41b901000000 41d3e1 448bc6 49c1e805 }
            // n = 6, score = 300
            //   8bce                 | test                esi, esi
            //   83e11f               | jne                 0xffffffdf
            //   41b901000000         | dec                 eax
            //   41d3e1               | lea                 ebx, [edi - 0x20]
            //   448bc6               | je                  0x80
            //   49c1e805             | dec                 eax

        $sequence_5 = { 488bfb 488bde 4885f6 75d7 }
            // n = 4, score = 300
            //   488bfb               | dec                 eax
            //   488bde               | mov                 edx, eax
            //   4885f6               | dec                 eax
            //   75d7                 | lea                 ecx, [ebp + 0x170]

        $sequence_6 = { 7512 488d9550010000 488b4d90 e8???????? eb02 ffcb }
            // n = 6, score = 300
            //   7512                 | mov                 ecx, esi
            //   488d9550010000       | and                 ecx, 0x1f
            //   488b4d90             | inc                 ecx
            //   e8????????           |                     
            //   eb02                 | mov                 ecx, 1
            //   ffcb                 | inc                 ecx

        $sequence_7 = { 4c8d8d10020000 4c8bc7 488bd0 488d8d70010000 }
            // n = 4, score = 300
            //   4c8d8d10020000       | dec                 esp
            //   4c8bc7               | lea                 ecx, [ebp + 0x210]
            //   488bd0               | dec                 esp
            //   488d8d70010000       | mov                 eax, edi

        $sequence_8 = { 837dc000 0f8414010000 83ec18 c745e800000000 }
            // n = 4, score = 100
            //   837dc000             | and                 al, 1
            //   0f8414010000         | test                al, al
            //   83ec18               | sete                bl
            //   c745e800000000       | xor                 al, al

        $sequence_9 = { 8d4dd8 c745fc00000000 e8???????? 8d4508 c645fc01 50 }
            // n = 6, score = 100
            //   8d4dd8               | test                al, al
            //   c745fc00000000       | mov                 byte ptr [ebp - 4], 0x34
            //   e8????????           |                     
            //   8d4508               | push                eax
            //   c645fc01             | lea                 ecx, [ebp - 0x12c]
            //   50                   | mov                 edi, eax

        $sequence_10 = { c645fc34 50 ba???????? 8d8dd4feffff e8???????? }
            // n = 5, score = 100
            //   c645fc34             | sete                bl
            //   50                   | jmp                 7
            //   ba????????           |                     
            //   8d8dd4feffff         | shr                 al, 4
            //   e8????????           |                     

        $sequence_11 = { 8bf8 8d85f4fdffff 50 56 }
            // n = 4, score = 100
            //   8bf8                 | and                 al, 1
            //   8d85f4fdffff         | test                al, al
            //   50                   | sete                bl
            //   56                   | shr                 al, 4

        $sequence_12 = { c6458300 8b4dc8 85c9 7409 }
            // n = 4, score = 100
            //   c6458300             | xor                 al, al
            //   8b4dc8               | jmp                 9
            //   85c9                 | shr                 al, 4
            //   7409                 | and                 al, 1

        $sequence_13 = { 8b45ec 8b75cc 3bc6 7557 8b36 }
            // n = 5, score = 100
            //   8b45ec               | jmp                 7
            //   8b75cc               | shr                 al, 4
            //   3bc6                 | and                 al, 1
            //   7557                 | test                al, al
            //   8b36                 | jne                 6

        $sequence_14 = { c785a8feffff00000000 c68598feffff00 83bd3cffffff10 720e ffb528ffffff e8???????? }
            // n = 6, score = 100
            //   c785a8feffff00000000     | lea    eax, [ebp - 0x20c]
            //   c68598feffff00       | push                eax
            //   83bd3cffffff10       | push                esi
            //   720e                 | cmp                 dword ptr [ebp - 0x40], 0
            //   ffb528ffffff         | je                  0x11a
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1933312
}
