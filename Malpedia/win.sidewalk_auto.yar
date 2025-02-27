rule win_sidewalk_auto {

    meta:
        id = "1zwrjdcKVoFsQA7nB66vK5"
        fingerprint = "v1_sha256_e6737ed096fc4d4ecc8ea3c0d1ac3b4b3bce3ee6030ce0fc8630ca3477945c10"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sidewalk."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sidewalk"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 41880408 48ffc1 488d040a 483bc6 7ce2 4883c640 }
            // n = 6, score = 200
            //   41880408             | add                 ebx, esi
            //   48ffc1               | inc                 esp
            //   488d040a             | add                 ebp, eax
            //   483bc6               | inc                 ecx
            //   7ce2                 | xor                 ebx, ebx
            //   4883c640             | inc                 ecx

        $sequence_1 = { 488d5204 4983e901 75d4 4863457f 33db }
            // n = 5, score = 200
            //   488d5204             | dec                 ecx
            //   4983e901             | sub                 ecx, 1
            //   75d4                 | shr                 eax, 0x10
            //   4863457f             | mov                 byte ptr [edx], cl
            //   33db                 | shr                 ecx, 0x18

        $sequence_2 = { c1e810 880a c1e918 884202 884a03 4183f810 }
            // n = 6, score = 200
            //   c1e810               | add                 ebx, esi
            //   880a                 | inc                 esp
            //   c1e918               | add                 ebp, eax
            //   884202               | inc                 ecx
            //   884a03               | xor                 ebx, ebx
            //   4183f810             | inc                 ecx

        $sequence_3 = { 8945ef 8bc2 33c6 c1c010 }
            // n = 4, score = 200
            //   8945ef               | inc                 esp
            //   8bc2                 | add                 ebx, edi
            //   33c6                 | inc                 ebp
            //   c1c010               | mov                 eax, ebx

        $sequence_4 = { 41c1c610 4503e6 4403cb 4533d1 }
            // n = 4, score = 200
            //   41c1c610             | inc                 ebp
            //   4503e6               | xor                 edx, ecx
            //   4403cb               | inc                 ecx
            //   4533d1               | xor                 eax, esi

        $sequence_5 = { 33f0 418bc1 4133c6 c1c608 c1c010 4403de }
            // n = 6, score = 200
            //   33f0                 | add                 ebx, eax
            //   418bc1               | inc                 ecx
            //   4133c6               | xor                 ebx, ebx
            //   c1c608               | rol                 ebx, 0xc
            //   c1c010               | xor                 esi, eax
            //   4403de               | inc                 ecx

        $sequence_6 = { c1e108 0bc8 0fb642fe c1e108 0bc8 41890c10 }
            // n = 6, score = 200
            //   c1e108               | add                 esp, esi
            //   0bc8                 | inc                 esp
            //   0fb642fe             | add                 ecx, ebx
            //   c1e108               | inc                 ebp
            //   0bc8                 | xor                 edx, ecx
            //   41890c10             | inc                 esp

        $sequence_7 = { 4403c8 4533d1 41c1c208 4503fa 418bdf 33d8 }
            // n = 6, score = 200
            //   4403c8               | rol                 edi, 0x10
            //   4533d1               | inc                 esp
            //   41c1c208             | add                 ebx, edi
            //   4503fa               | inc                 ecx
            //   418bdf               | rol                 esi, 0x10
            //   33d8                 | inc                 esp

        $sequence_8 = { 33c3 c1c207 c1c00c 4403c8 4533d1 41c1c208 }
            // n = 6, score = 200
            //   33c3                 | inc                 esp
            //   c1c207               | add                 ebx, edi
            //   c1c00c               | inc                 ecx
            //   4403c8               | rol                 esi, 0x10
            //   4533d1               | inc                 ebp
            //   41c1c208             | add                 esp, esi

        $sequence_9 = { 33c6 c1c010 4403d8 4133db c1c30c 03d3 }
            // n = 6, score = 200
            //   33c6                 | xor                 eax, esi
            //   c1c010               | rol                 eax, 0x10
            //   4403d8               | inc                 esp
            //   4133db               | add                 ebx, eax
            //   c1c30c               | inc                 ecx
            //   03d3                 | xor                 ebx, ebx

        $sequence_10 = { 4403cb 4533d1 4403ee 41c1c210 }
            // n = 4, score = 200
            //   4403cb               | xor                 esi, edx
            //   4533d1               | rol                 edi, 0x10
            //   4403ee               | inc                 esp
            //   41c1c210             | add                 ebx, edi

        $sequence_11 = { 4403e8 4133db 418bcd c1c307 }
            // n = 4, score = 200
            //   4403e8               | rol                 edx, 0x10
            //   4133db               | inc                 ecx
            //   418bcd               | mov                 eax, ebx
            //   c1c307               | inc                 ecx

        $sequence_12 = { 0bc8 41890c10 488d5204 4983e901 }
            // n = 4, score = 200
            //   0bc8                 | rol                 ebx, 0xc
            //   41890c10             | add                 edx, ebx
            //   488d5204             | mov                 esi, edx
            //   4983e901             | inc                 esp

        $sequence_13 = { 418bc0 c1e002 4d8d4904 4863d0 41ffc0 }
            // n = 5, score = 200
            //   418bc0               | add                 ebx, edi
            //   c1e002               | inc                 ecx
            //   4d8d4904             | rol                 esi, 0x10
            //   4863d0               | inc                 ebp
            //   41ffc0               | add                 esp, esi

        $sequence_14 = { 7d15 8a040f 3201 41880408 48ffc1 }
            // n = 5, score = 200
            //   7d15                 | xor                 ebx, ebx
            //   8a040f               | inc                 ecx
            //   3201                 | mov                 ecx, ebp
            //   41880408             | inc                 ecx
            //   48ffc1               | xor                 ebx, ebx

        $sequence_15 = { 4133f8 c1c610 4433f2 c1c710 4403df }
            // n = 5, score = 200
            //   4133f8               | mov                 eax, ecx
            //   c1c610               | inc                 ecx
            //   4433f2               | xor                 eax, esi
            //   c1c710               | rol                 esi, 8
            //   4403df               | rol                 eax, 0x10

    condition:
        7 of them and filesize < 237568
}
