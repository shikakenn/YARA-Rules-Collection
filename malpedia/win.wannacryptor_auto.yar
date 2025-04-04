rule win_wannacryptor_auto {

    meta:
        id = "70bkGHNY3OsDatddTJWUM7"
        fingerprint = "v1_sha256_afdf6a6730d9f47a6baac4eceac9faa53fb74580c5a732dc9532925b43ed27e8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.wannacryptor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wannacryptor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83f802 757f 8b5674 8d7e44 8d442414 52 }
            // n = 6, score = 700
            //   83f802               | cmp                 eax, 2
            //   757f                 | jne                 0x81
            //   8b5674               | mov                 edx, dword ptr [esi + 0x74]
            //   8d7e44               | lea                 edi, [esi + 0x44]
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   52                   | push                edx

        $sequence_1 = { 23c3 8b5c2468 53 8b5c2468 53 }
            // n = 5, score = 700
            //   23c3                 | and                 eax, ebx
            //   8b5c2468             | mov                 ebx, dword ptr [esp + 0x68]
            //   53                   | push                ebx
            //   8b5c2468             | mov                 ebx, dword ptr [esp + 0x68]
            //   53                   | push                ebx

        $sequence_2 = { 8b16 c1f805 0faff8 897e04 8b4160 03c2 }
            // n = 6, score = 700
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   c1f805               | sar                 eax, 5
            //   0faff8               | imul                edi, eax
            //   897e04               | mov                 dword ptr [esi + 4], edi
            //   8b4160               | mov                 eax, dword ptr [ecx + 0x60]
            //   03c2                 | add                 eax, edx

        $sequence_3 = { 8d542418 c744243005000000 8b41f8 8b4e74 2bc1 }
            // n = 5, score = 700
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   c744243005000000     | mov                 dword ptr [esp + 0x30], 5
            //   8b41f8               | mov                 eax, dword ptr [ecx - 8]
            //   8b4e74               | mov                 ecx, dword ptr [esi + 0x74]
            //   2bc1                 | sub                 eax, ecx

        $sequence_4 = { 51 885c243c e8???????? 50 8bcf c644243404 }
            // n = 6, score = 700
            //   51                   | push                ecx
            //   885c243c             | mov                 byte ptr [esp + 0x3c], bl
            //   e8????????           |                     
            //   50                   | push                eax
            //   8bcf                 | mov                 ecx, edi
            //   c644243404           | mov                 byte ptr [esp + 0x34], 4

        $sequence_5 = { 8d4c241c 6a01 51 8a02 8bcf 88442418 }
            // n = 6, score = 700
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   8a02                 | mov                 al, byte ptr [edx]
            //   8bcf                 | mov                 ecx, edi
            //   88442418             | mov                 byte ptr [esp + 0x18], al

        $sequence_6 = { 7e76 8bd8 8b5500 03cf 8a0417 50 }
            // n = 6, score = 700
            //   7e76                 | jle                 0x78
            //   8bd8                 | mov                 ebx, eax
            //   8b5500               | mov                 edx, dword ptr [ebp]
            //   03cf                 | add                 ecx, edi
            //   8a0417               | mov                 al, byte ptr [edi + edx]
            //   50                   | push                eax

        $sequence_7 = { 8d442420 f7d8 1bc0 682000cc00 23c3 8b5c2468 53 }
            // n = 7, score = 700
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   682000cc00           | push                0xcc0020
            //   23c3                 | and                 eax, ebx
            //   8b5c2468             | mov                 ebx, dword ptr [esp + 0x68]
            //   53                   | push                ebx

        $sequence_8 = { 0f8c42ffffff 8b442438 5f 85c0 7403 }
            // n = 5, score = 700
            //   0f8c42ffffff         | jl                  0xffffff48
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   5f                   | pop                 edi
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_9 = { 8a1401 8d4c2460 8854243c 8b44243c }
            // n = 4, score = 700
            //   8a1401               | mov                 dl, byte ptr [ecx + eax]
            //   8d4c2460             | lea                 ecx, [esp + 0x60]
            //   8854243c             | mov                 byte ptr [esp + 0x3c], dl
            //   8b44243c             | mov                 eax, dword ptr [esp + 0x3c]

    condition:
        7 of them and filesize < 540672
}
