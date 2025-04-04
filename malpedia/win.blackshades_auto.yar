rule win_blackshades_auto {

    meta:
        id = "44SXtM78bUpwZeaAu3Ue3o"
        fingerprint = "v1_sha256_5be1fd8de19e4a88da957f4843427153e72a697b528878c27f4d0e3032429536"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.blackshades."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackshades"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff9e0460ff34 6c 60 ff0a }
            // n = 4, score = 100
            //   ff9e0460ff34         | lcall               [esi + 0x34ff6004]
            //   6c                   | insb                byte ptr es:[edi], dx
            //   60                   | pushal              
            //   ff0a                 | dec                 dword ptr [edx]

        $sequence_1 = { 08fe f5 0200 0000 6c 70ff 9e }
            // n = 7, score = 100
            //   08fe                 | or                  dh, bh
            //   f5                   | cmc                 
            //   0200                 | add                 al, byte ptr [eax]
            //   0000                 | add                 byte ptr [eax], al
            //   6c                   | insb                byte ptr es:[edi], dx
            //   70ff                 | jo                  1
            //   9e                   | sahf                

        $sequence_2 = { 70ff f30004eb f4 02eb fb cf }
            // n = 6, score = 100
            //   70ff                 | jo                  1
            //   f30004eb             | add                 byte ptr [ebx + ebp*8], al
            //   f4                   | hlt                 
            //   02eb                 | add                 ch, bl
            //   fb                   | sti                 
            //   cf                   | iretd               

        $sequence_3 = { 351cff1e55 2c00 0d6c04ff1b c700fb301cc9 }
            // n = 4, score = 100
            //   351cff1e55           | xor                 eax, 0x551eff1c
            //   2c00                 | sub                 al, 0
            //   0d6c04ff1b           | or                  eax, 0x1bff046c
            //   c700fb301cc9         | mov                 dword ptr [eax], 0xc91c30fb

        $sequence_4 = { 58 2f 60 ff6c74ff }
            // n = 4, score = 100
            //   58                   | pop                 eax
            //   2f                   | das                 
            //   60                   | pushal              
            //   ff6c74ff             | ljmp                [esp + esi*2 - 1]

        $sequence_5 = { 2a23 60 ff1b 0d002a460c fff5 0200 0000 }
            // n = 7, score = 100
            //   2a23                 | sub                 ah, byte ptr [ebx]
            //   60                   | pushal              
            //   ff1b                 | lcall               [ebx]
            //   0d002a460c           | or                  eax, 0xc462a00
            //   fff5                 | push                ebp
            //   0200                 | add                 al, byte ptr [eax]
            //   0000                 | add                 byte ptr [eax], al

        $sequence_6 = { 6c ff4a71 70ff 00746c78 ff1b }
            // n = 5, score = 100
            //   6c                   | insb                byte ptr es:[edi], dx
            //   ff4a71               | dec                 dword ptr [edx + 0x71]
            //   70ff                 | jo                  1
            //   00746c78             | add                 byte ptr [esp + ebp*2 + 0x78], dh
            //   ff1b                 | lcall               [ebx]

        $sequence_7 = { 6c ff4a71 70ff 00746c78 ff1b 4a }
            // n = 6, score = 100
            //   6c                   | insb                byte ptr es:[edi], dx
            //   ff4a71               | dec                 dword ptr [edx + 0x71]
            //   70ff                 | jo                  1
            //   00746c78             | add                 byte ptr [esp + ebp*2 + 0x78], dh
            //   ff1b                 | lcall               [ebx]
            //   4a                   | dec                 edx

        $sequence_8 = { ff6c48ff 6c 4c ff40fc }
            // n = 4, score = 100
            //   ff6c48ff             | ljmp                [eax + ecx*2 - 1]
            //   6c                   | insb                byte ptr es:[edi], dx
            //   4c                   | dec                 esp
            //   ff40fc               | inc                 dword ptr [eax - 4]

        $sequence_9 = { ff1b 0d002a460c fff5 0200 0000 6c }
            // n = 6, score = 100
            //   ff1b                 | lcall               [ebx]
            //   0d002a460c           | or                  eax, 0xc462a00
            //   fff5                 | push                ebp
            //   0200                 | add                 al, byte ptr [eax]
            //   0000                 | add                 byte ptr [eax], al
            //   6c                   | insb                byte ptr es:[edi], dx

    condition:
        7 of them and filesize < 999424
}
