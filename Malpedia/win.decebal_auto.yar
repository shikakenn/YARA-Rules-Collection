rule win_decebal_auto {

    meta:
        id = "2qNvAaWbZ0EIqUpq3vXpQ3"
        fingerprint = "v1_sha256_d2229dc1b2586911890a50d89e439f882a782aa61b00f38971db65483a51bfa5"
        version = "1"
        date = "2018-11-23"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator 0.1a"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.decebal"
        malpedia_version = "20180607"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff250c104000 ff2550104000 ff2570104000 ff2518104000 }
            // n = 4, score = 1000
            //   ff250c104000         | jmp                 dword ptr [0x40100c]
            //   ff2550104000         | jmp                 dword ptr [0x401050]
            //   ff2570104000         | jmp                 dword ptr [0x401070]
            //   ff2518104000         | jmp                 dword ptr [0x401018]

        $sequence_1 = { ff256c104000 ff2538104000 ff2558104000 ff2534104000 }
            // n = 4, score = 1000
            //   ff256c104000         | jmp                 dword ptr [0x40106c]
            //   ff2538104000         | jmp                 dword ptr [0x401038]
            //   ff2558104000         | jmp                 dword ptr [0x401058]
            //   ff2534104000         | jmp                 dword ptr [0x401034]

        $sequence_2 = { ff2504104000 ff2564104000 ff2520104000 ff2514104000 }
            // n = 4, score = 1000
            //   ff2504104000         | jmp                 dword ptr [0x401004]
            //   ff2564104000         | jmp                 dword ptr [0x401064]
            //   ff2520104000         | jmp                 dword ptr [0x401020]
            //   ff2514104000         | jmp                 dword ptr [0x401014]

        $sequence_3 = { ff2528104000 ff2540104000 ff2574104000 ff2544104000 }
            // n = 4, score = 1000
            //   ff2528104000         | jmp                 dword ptr [0x401028]
            //   ff2540104000         | jmp                 dword ptr [0x401040]
            //   ff2574104000         | jmp                 dword ptr [0x401074]
            //   ff2544104000         | jmp                 dword ptr [0x401044]

        $sequence_4 = { ff2548104000 ff253c104000 ff256c104000 ff2538104000 }
            // n = 4, score = 1000
            //   ff2548104000         | jmp                 dword ptr [0x401048]
            //   ff253c104000         | jmp                 dword ptr [0x40103c]
            //   ff256c104000         | jmp                 dword ptr [0x40106c]
            //   ff2538104000         | jmp                 dword ptr [0x401038]

        $sequence_5 = { ff2520104000 ff2514104000 ff2510104000 ff2554104000 }
            // n = 4, score = 1000
            //   ff2520104000         | jmp                 dword ptr [0x401020]
            //   ff2514104000         | jmp                 dword ptr [0x401014]
            //   ff2510104000         | jmp                 dword ptr [0x401010]
            //   ff2554104000         | jmp                 dword ptr [0x401054]

        $sequence_6 = { ff2574104000 ff2544104000 ff251c104000 ff2548104000 }
            // n = 4, score = 1000
            //   ff2574104000         | jmp                 dword ptr [0x401074]
            //   ff2544104000         | jmp                 dword ptr [0x401044]
            //   ff251c104000         | jmp                 dword ptr [0x40101c]
            //   ff2548104000         | jmp                 dword ptr [0x401048]

        $sequence_7 = { ff254c104000 ff2508104000 ff255c104000 ff2560104000 }
            // n = 4, score = 1000
            //   ff254c104000         | jmp                 dword ptr [0x40104c]
            //   ff2508104000         | jmp                 dword ptr [0x401008]
            //   ff255c104000         | jmp                 dword ptr [0x40105c]
            //   ff2560104000         | jmp                 dword ptr [0x401060]

        $sequence_8 = { ff252c104000 ff250c104000 ff2550104000 ff2570104000 }
            // n = 4, score = 1000
            //   ff252c104000         | jmp                 dword ptr [0x40102c]
            //   ff250c104000         | jmp                 dword ptr [0x40100c]
            //   ff2550104000         | jmp                 dword ptr [0x401050]
            //   ff2570104000         | jmp                 dword ptr [0x401070]

        $sequence_9 = { ff2550104000 ff2570104000 ff2518104000 ff2504104000 }
            // n = 4, score = 1000
            //   ff2550104000         | jmp                 dword ptr [0x401050]
            //   ff2570104000         | jmp                 dword ptr [0x401070]
            //   ff2518104000         | jmp                 dword ptr [0x401018]
            //   ff2504104000         | jmp                 dword ptr [0x401004]

    condition:
        7 of them
}
