rule win_happy_locker_auto {

    meta:
        id = "587Aa5KDesRhQXSukhUgzS"
        fingerprint = "v1_sha256_598b3afe6e6b46912fc4a600936a67f1af07eda2a62b596c3fe59dad2de38eed"
        version = "1"
        date = "2020-05-30"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.4.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.happy_locker"
        malpedia_rule_date = "20200529"
        malpedia_hash = "92c362319514e5a6da26204961446caa3a8b32a8"
        malpedia_version = "20200529"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 87c4 f9 ff2b 99 f7ff 2094f7ff2094f7 ff20 }
            // n = 7, score = 100
            //   87c4                 | xchg                esp, eax
            //   f9                   | stc                 
            //   ff2b                 | ljmp                [ebx]
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi
            //   2094f7ff2094f7       | and                 byte ptr [edi + esi*8 - 0x86bdf01], dl
            //   ff20                 | jmp                 dword ptr [eax]

        $sequence_1 = { f9 ff2b 99 f7ff }
            // n = 4, score = 100
            //   f9                   | stc                 
            //   ff2b                 | ljmp                [ebx]
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi

        $sequence_2 = { 2094f7ff2094f7 ff20 94 f7ff 2094f7ff2094f7 ff20 }
            // n = 6, score = 100
            //   2094f7ff2094f7       | and                 byte ptr [edi + esi*8 - 0x86bdf01], dl
            //   ff20                 | jmp                 dword ptr [eax]
            //   94                   | xchg                eax, esp
            //   f7ff                 | idiv                edi
            //   2094f7ff2094f7       | and                 byte ptr [edi + esi*8 - 0x86bdf01], dl
            //   ff20                 | jmp                 dword ptr [eax]

        $sequence_3 = { 0000 1c93 f6901f94f7fe 2094f7ff369ef7 ff4da8 f7ff }
            // n = 6, score = 100
            //   0000                 | add                 byte ptr [eax], al
            //   1c93                 | sbb                 al, 0x93
            //   f6901f94f7fe         | not                 byte ptr [eax - 0x1086be1]
            //   2094f7ff369ef7       | and                 byte ptr [edi + esi*8 - 0x861c901], dl
            //   ff4da8               | dec                 dword ptr [ebp - 0x58]
            //   f7ff                 | idiv                edi

        $sequence_4 = { 99 f7ff 2094f7ff2094f7 ff20 94 f7ff 2094f7ff2094f7 }
            // n = 7, score = 100
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi
            //   2094f7ff2094f7       | and                 byte ptr [edi + esi*8 - 0x86bdf01], dl
            //   ff20                 | jmp                 dword ptr [eax]
            //   94                   | xchg                eax, esp
            //   f7ff                 | idiv                edi
            //   2094f7ff2094f7       | and                 byte ptr [edi + esi*8 - 0x86bdf01], dl

        $sequence_5 = { f6901f94f7fe 2094f7ff369ef7 ff4da8 f7ff 9d cf }
            // n = 6, score = 100
            //   f6901f94f7fe         | not                 byte ptr [eax - 0x1086be1]
            //   2094f7ff369ef7       | and                 byte ptr [edi + esi*8 - 0x861c901], dl
            //   ff4da8               | dec                 dword ptr [ebp - 0x58]
            //   f7ff                 | idiv                edi
            //   9d                   | popfd               
            //   cf                   | iretd               

        $sequence_6 = { 94 f7ff 2094f7ff2094f7 ff20 94 f7ff }
            // n = 6, score = 100
            //   94                   | xchg                eax, esp
            //   f7ff                 | idiv                edi
            //   2094f7ff2094f7       | and                 byte ptr [edi + esi*8 - 0x86bdf01], dl
            //   ff20                 | jmp                 dword ptr [eax]
            //   94                   | xchg                eax, esp
            //   f7ff                 | idiv                edi

        $sequence_7 = { 87c4 f9 ff2b 99 }
            // n = 4, score = 100
            //   87c4                 | xchg                esp, eax
            //   f9                   | stc                 
            //   ff2b                 | ljmp                [ebx]
            //   99                   | cdq                 

        $sequence_8 = { 0000 1c93 f6901f94f7fe 2094f7ff369ef7 ff4da8 f7ff 9d }
            // n = 7, score = 100
            //   0000                 | add                 byte ptr [eax], al
            //   1c93                 | sbb                 al, 0x93
            //   f6901f94f7fe         | not                 byte ptr [eax - 0x1086be1]
            //   2094f7ff369ef7       | and                 byte ptr [edi + esi*8 - 0x861c901], dl
            //   ff4da8               | dec                 dword ptr [ebp - 0x58]
            //   f7ff                 | idiv                edi
            //   9d                   | popfd               

        $sequence_9 = { 99 f7ff 2094f7ff2094f7 ff20 }
            // n = 4, score = 100
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi
            //   2094f7ff2094f7       | and                 byte ptr [edi + esi*8 - 0x86bdf01], dl
            //   ff20                 | jmp                 dword ptr [eax]

    condition:
        7 of them and filesize < 2400256
}
