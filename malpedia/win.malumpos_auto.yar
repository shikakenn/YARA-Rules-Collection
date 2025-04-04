rule win_malumpos_auto {

    meta:
        id = "2babxv0suOwaX2KPcZZW4I"
        fingerprint = "v1_sha256_3114be15227a95c744ccca089995ccddd28287774a7cad476fe879d040c5b1ad"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.malumpos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.malumpos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 25ffffffff f8 ff45fc 0fb705???????? 8b55fc 8d0441 }
            // n = 6, score = 100
            //   25ffffffff           | and                 eax, 0xffffffff
            //   f8                   | clc                 
            //   ff45fc               | inc                 dword ptr [ebp - 4]
            //   0fb705????????       |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8d0441               | lea                 eax, [ecx + eax*2]

        $sequence_1 = { 750b 68???????? e8???????? 59 8d45cc }
            // n = 5, score = 100
            //   750b                 | jne                 0xd
            //   68????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8d45cc               | lea                 eax, [ebp - 0x34]

        $sequence_2 = { 57 2d00000000 5f 7b03 f6c7cb 0af6 f7c344f267d3 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   2d00000000           | sub                 eax, 0
            //   5f                   | pop                 edi
            //   7b03                 | jnp                 5
            //   f6c7cb               | test                bh, 0xcb
            //   0af6                 | or                  dh, dh
            //   f7c344f267d3         | test                ebx, 0xd367f244

        $sequence_3 = { 5b 7c05 53 80c400 5b }
            // n = 5, score = 100
            //   5b                   | pop                 ebx
            //   7c05                 | jl                  7
            //   53                   | push                ebx
            //   80c400               | add                 ah, 0
            //   5b                   | pop                 ebx

        $sequence_4 = { 5f 5f 5f 90 7b07 56 7603 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5f                   | pop                 edi
            //   5f                   | pop                 edi
            //   90                   | nop                 
            //   7b07                 | jnp                 9
            //   56                   | push                esi
            //   7603                 | jbe                 5

        $sequence_5 = { 7805 0500000000 57 3500000000 }
            // n = 4, score = 100
            //   7805                 | js                  7
            //   0500000000           | add                 eax, 0
            //   57                   | push                edi
            //   3500000000           | xor                 eax, 0

        $sequence_6 = { 8a0432 3c3d 7506 8365fc00 eb0d }
            // n = 5, score = 100
            //   8a0432               | mov                 al, byte ptr [edx + esi]
            //   3c3d                 | cmp                 al, 0x3d
            //   7506                 | jne                 8
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   eb0d                 | jmp                 0xf

        $sequence_7 = { 7429 8b45f4 3b4618 7321 }
            // n = 4, score = 100
            //   7429                 | je                  0x2b
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   3b4618               | cmp                 eax, dword ptr [esi + 0x18]
            //   7321                 | jae                 0x23

        $sequence_8 = { a3???????? 391d???????? 7515 be???????? e8???????? 50 }
            // n = 6, score = 100
            //   a3????????           |                     
            //   391d????????         |                     
            //   7515                 | jne                 0x17
            //   be????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_9 = { 66a94a47 83c000 56 7e04 57 85c9 }
            // n = 6, score = 100
            //   66a94a47             | test                ax, 0x474a
            //   83c000               | add                 eax, 0
            //   56                   | push                esi
            //   7e04                 | jle                 6
            //   57                   | push                edi
            //   85c9                 | test                ecx, ecx

    condition:
        7 of them and filesize < 542720
}
