rule win_mirrorkey_auto {

    meta:
        id = "5RqXbU08pKL6meYTmeIimP"
        fingerprint = "v1_sha256_45136c9373865a91139e9dff7c71e7f62a2de8b30b90c9e3be875470ec9069c0"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mirrorkey."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mirrorkey"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 32c2 8b5508 32c1 8802 83c204 }
            // n = 5, score = 100
            //   32c2                 | xor                 al, dl
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   32c1                 | xor                 al, cl
            //   8802                 | mov                 byte ptr [edx], al
            //   83c204               | add                 edx, 4

        $sequence_1 = { 8a1c19 8d4f01 81e103000080 7905 49 83c9fc }
            // n = 6, score = 100
            //   8a1c19               | mov                 bl, byte ptr [ecx + ebx]
            //   8d4f01               | lea                 ecx, [edi + 1]
            //   81e103000080         | and                 ecx, 0x80000003
            //   7905                 | jns                 7
            //   49                   | dec                 ecx
            //   83c9fc               | or                  ecx, 0xfffffffc

        $sequence_2 = { 8945d4 85c0 745a ff75d0 8d45d4 50 e8???????? }
            // n = 7, score = 100
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   85c0                 | test                eax, eax
            //   745a                 | je                  0x5c
            //   ff75d0               | push                dword ptr [ebp - 0x30]
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { 8d4de8 57 8b13 0f57c0 }
            // n = 4, score = 100
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   57                   | push                edi
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   0f57c0               | xorps               xmm0, xmm0

        $sequence_4 = { 0f434dd8 8b01 8907 8b4104 8d4dc0 }
            // n = 5, score = 100
            //   0f434dd8             | cmovae              ecx, dword ptr [ebp - 0x28]
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8907                 | mov                 dword ptr [edi], eax
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]

        $sequence_5 = { 8d4f04 894dfc 8b07 03c2 7460 }
            // n = 5, score = 100
            //   8d4f04               | lea                 ecx, [edi + 4]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   03c2                 | add                 eax, edx
            //   7460                 | je                  0x62

        $sequence_6 = { 03c2 75ab 5e 5b 5f }
            // n = 5, score = 100
            //   03c2                 | add                 eax, edx
            //   75ab                 | jne                 0xffffffad
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi

        $sequence_7 = { 53 8b5f38 56 8b7754 4e }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   8b5f38               | mov                 ebx, dword ptr [edi + 0x38]
            //   56                   | push                esi
            //   8b7754               | mov                 esi, dword ptr [edi + 0x54]
            //   4e                   | dec                 esi

        $sequence_8 = { 33c0 5e 5d c20800 8b5508 }
            // n = 5, score = 100
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_9 = { 03c7 8945ec 8b441724 03c7 8945f8 }
            // n = 5, score = 100
            //   03c7                 | add                 eax, edi
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b441724             | mov                 eax, dword ptr [edi + edx + 0x24]
            //   03c7                 | add                 eax, edi
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

    condition:
        7 of them and filesize < 117760
}
