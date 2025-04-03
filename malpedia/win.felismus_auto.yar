rule win_felismus_auto {

    meta:
        id = "J6E2IZujVALOawHSRc4bU"
        fingerprint = "v1_sha256_4546b8db4538dafe5bc8d041a61c766239a1afc6f98e209750b1eab9012fff52"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.felismus."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.felismus"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 55 8b2d???????? ffd5 8bbc24000a0000 b908000000 8d742420 53 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8b2d????????         |                     
            //   ffd5                 | call                ebp
            //   8bbc24000a0000       | mov                 edi, dword ptr [esp + 0xa00]
            //   b908000000           | mov                 ecx, 8
            //   8d742420             | lea                 esi, [esp + 0x20]
            //   53                   | push                ebx

        $sequence_1 = { 51 8bcd e8???????? eb2e 83f803 7519 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   8bcd                 | mov                 ecx, ebp
            //   e8????????           |                     
            //   eb2e                 | jmp                 0x30
            //   83f803               | cmp                 eax, 3
            //   7519                 | jne                 0x1b

        $sequence_2 = { 8bf0 e8???????? 83c418 8945e0 56 68???????? 50 }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   56                   | push                esi
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_3 = { e9???????? 8b442410 5f c6450000 5e 5d 5b }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   5f                   | pop                 edi
            //   c6450000             | mov                 byte ptr [ebp], 0
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_4 = { 5b 81c4b4010000 c3 55 ffd3 8b4c2414 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   81c4b4010000         | add                 esp, 0x1b4
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   ffd3                 | call                ebx
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]

        $sequence_5 = { 8a840620420110 884201 33c0 8a4102 }
            // n = 4, score = 100
            //   8a840620420110       | mov                 al, byte ptr [esi + eax + 0x10014220]
            //   884201               | mov                 byte ptr [edx + 1], al
            //   33c0                 | xor                 eax, eax
            //   8a4102               | mov                 al, byte ptr [ecx + 2]

        $sequence_6 = { d3ee 8b0d???????? d3e7 8b4c2474 0bf7 8b7834 03f1 }
            // n = 7, score = 100
            //   d3ee                 | shr                 esi, cl
            //   8b0d????????         |                     
            //   d3e7                 | shl                 edi, cl
            //   8b4c2474             | mov                 ecx, dword ptr [esp + 0x74]
            //   0bf7                 | or                  esi, edi
            //   8b7834               | mov                 edi, dword ptr [eax + 0x34]
            //   03f1                 | add                 esi, ecx

        $sequence_7 = { 83c404 57 ff15???????? 8b5dec e9???????? b911000000 33c0 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8b5dec               | mov                 ebx, dword ptr [ebp - 0x14]
            //   e9????????           |                     
            //   b911000000           | mov                 ecx, 0x11
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { 83c40c f2ae f7d1 2bf9 8d95f4fdffff 8bf7 8bfa }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   8d95f4fdffff         | lea                 edx, [ebp - 0x20c]
            //   8bf7                 | mov                 esi, edi
            //   8bfa                 | mov                 edi, edx

        $sequence_9 = { 33ff 85db 7e7f ff15???????? 99 b91a000000 }
            // n = 6, score = 100
            //   33ff                 | xor                 edi, edi
            //   85db                 | test                ebx, ebx
            //   7e7f                 | jle                 0x81
            //   ff15????????         |                     
            //   99                   | cdq                 
            //   b91a000000           | mov                 ecx, 0x1a

    condition:
        7 of them and filesize < 204800
}
