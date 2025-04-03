rule win_brutpos_auto {

    meta:
        id = "5cv9ab1MfAit5eaaA5NjW5"
        fingerprint = "v1_sha256_89d0bc6a7e52ba9f63dface96ebbf483b03be0cbf8144ed32f3b88bf360b4eda"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.brutpos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.brutpos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 59 58 83c004 83e904 8808 }
            // n = 5, score = 100
            //   59                   | pop                 ecx
            //   58                   | pop                 eax
            //   83c004               | add                 eax, 4
            //   83e904               | sub                 ecx, 4
            //   8808                 | mov                 byte ptr [eax], cl

        $sequence_1 = { 03c2 034508 2938 83e902 75e8 ebd9 5e }
            // n = 7, score = 100
            //   03c2                 | add                 eax, edx
            //   034508               | add                 eax, dword ptr [ebp + 8]
            //   2938                 | sub                 dword ptr [eax], edi
            //   83e902               | sub                 ecx, 2
            //   75e8                 | jne                 0xffffffea
            //   ebd9                 | jmp                 0xffffffdb
            //   5e                   | pop                 esi

        $sequence_2 = { 8d5b18 8b5b60 03d8 52 8b35???????? }
            // n = 5, score = 100
            //   8d5b18               | lea                 ebx, [ebx + 0x18]
            //   8b5b60               | mov                 ebx, dword ptr [ebx + 0x60]
            //   03d8                 | add                 ebx, eax
            //   52                   | push                edx
            //   8b35????????         |                     

        $sequence_3 = { 6681f9df77 7412 0f31 8bd8 }
            // n = 4, score = 100
            //   6681f9df77           | cmp                 cx, 0x77df
            //   7412                 | je                  0x14
            //   0f31                 | rdtsc               
            //   8bd8                 | mov                 ebx, eax

        $sequence_4 = { 8bd0 ad 8bc8 83e908 66ad 6685c0 740c }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   83e908               | sub                 ecx, 8
            //   66ad                 | lodsw               ax, word ptr [esi]
            //   6685c0               | test                ax, ax
            //   740c                 | je                  0xe

        $sequence_5 = { 8d7c38fc baffffffff 83c704 57 }
            // n = 4, score = 100
            //   8d7c38fc             | lea                 edi, [eax + edi - 4]
            //   baffffffff           | mov                 edx, 0xffffffff
            //   83c704               | add                 edi, 4
            //   57                   | push                edi

        $sequence_6 = { 66ad 6685c0 740c 25ff0f0000 03c2 034508 }
            // n = 6, score = 100
            //   66ad                 | lodsw               ax, word ptr [esi]
            //   6685c0               | test                ax, ax
            //   740c                 | je                  0xe
            //   25ff0f0000           | and                 eax, 0xfff
            //   03c2                 | add                 eax, edx
            //   034508               | add                 eax, dword ptr [ebp + 8]

        $sequence_7 = { 52 e8???????? 59 8b09 8bd1 }
            // n = 5, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   8bd1                 | mov                 edx, ecx

        $sequence_8 = { c1e202 03d3 8b12 03d0 }
            // n = 4, score = 100
            //   c1e202               | shl                 edx, 2
            //   03d3                 | add                 edx, ebx
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   03d0                 | add                 edx, eax

        $sequence_9 = { 8b5508 8b4204 0fb70a 50 51 807401ff97 }
            // n = 6, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   0fb70a               | movzx               ecx, word ptr [edx]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   807401ff97           | xor                 byte ptr [ecx + eax - 1], 0x97

    condition:
        7 of them and filesize < 65536
}
