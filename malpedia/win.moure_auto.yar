rule win_moure_auto {

    meta:
        id = "5E3aDPPr1VVpydjrDIpKAa"
        fingerprint = "v1_sha256_e394b210e6ac1eaa6569608ddb349d4dd1ae50231f20d0924074c460f1fa6782"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.moure."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moure"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3454 43 1558c950cb 0d487b0d4c 36a373801f1e }
            // n = 5, score = 100
            //   3454                 | xor                 al, 0x54
            //   43                   | inc                 ebx
            //   1558c950cb           | adc                 eax, 0xcb50c958
            //   0d487b0d4c           | or                  eax, 0x4c0d7b48
            //   36a373801f1e         | mov                 dword ptr ss:[0x1e1f8073], eax

        $sequence_1 = { bf55602540 006b05 bc7d506700 0033 58 bf35b8bf55 58 }
            // n = 7, score = 100
            //   bf55602540           | mov                 edi, 0x40256055
            //   006b05               | add                 byte ptr [ebx + 5], ch
            //   bc7d506700           | mov                 esp, 0x67507d
            //   0033                 | add                 byte ptr [ebx], dh
            //   58                   | pop                 eax
            //   bf35b8bf55           | mov                 edi, 0x55bfb835
            //   58                   | pop                 eax

        $sequence_2 = { 8b35???????? 57 00d6 0075f0 894508 0075fc 00d6 }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   57                   | push                edi
            //   00d6                 | add                 dh, dl
            //   0075f0               | add                 byte ptr [ebp - 0x10], dh
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   0075fc               | add                 byte ptr [ebp - 4], dh
            //   00d6                 | add                 dh, dl

        $sequence_3 = { 51 51 8b0d???????? 56 33f6 85c9 7509 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   8b0d????????         |                     
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   85c9                 | test                ecx, ecx
            //   7509                 | jne                 0xb

        $sequence_4 = { 837dbc00 7436 0075bc 8d4ddc e8???????? a1???????? 3bc6 }
            // n = 7, score = 100
            //   837dbc00             | cmp                 dword ptr [ebp - 0x44], 0
            //   7436                 | je                  0x38
            //   0075bc               | add                 byte ptr [ebp - 0x44], dh
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   e8????????           |                     
            //   a1????????           |                     
            //   3bc6                 | cmp                 eax, esi

        $sequence_5 = { 82a8a200b000c1 8b00 e100 9e d28bd3977e8d 98 }
            // n = 6, score = 100
            //   82a8a200b000c1       | sub                 byte ptr [eax + 0xb000a2], 0xc1
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   e100                 | loope               2
            //   9e                   | sahf                
            //   d28bd3977e8d         | ror                 byte ptr [ebx - 0x7281682d], cl
            //   98                   | cwde                

        $sequence_6 = { 68b0704000 007014 007010 e8???????? }
            // n = 4, score = 100
            //   68b0704000           | push                0x4070b0
            //   007014               | add                 byte ptr [eax + 0x14], dh
            //   007010               | add                 byte ptr [eax + 0x10], dh
            //   e8????????           |                     

        $sequence_7 = { 5e 53 43 c1c361 5b c9 51 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   53                   | push                ebx
            //   43                   | inc                 ebx
            //   c1c361               | rol                 ebx, 0x61
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   51                   | push                ecx

        $sequence_8 = { 8b01 83e03f 3c02 751c 8b4514 8b10 83e23f }
            // n = 7, score = 100
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   83e03f               | and                 eax, 0x3f
            //   3c02                 | cmp                 al, 2
            //   751c                 | jne                 0x1e
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   83e23f               | and                 edx, 0x3f

        $sequence_9 = { 42 c3 874226 c58035b4fe70 5e }
            // n = 5, score = 100
            //   42                   | inc                 edx
            //   c3                   | ret                 
            //   874226               | xchg                dword ptr [edx + 0x26], eax
            //   c58035b4fe70         | lds                 eax, ptr [eax + 0x70feb435]
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 188416
}
