rule Linux_Rootkit_Reptile_b2ccf852 {
    meta:
        id = "19vfkUkdOnHrR4798BOdpl"
        fingerprint = "v1_sha256_efb4c0a9894e09b5a2a614a02810524e66b21f00b76ad583cc1eb551f4a73dcc"
        version = "1.0"
        date = "2024-11-13"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $func1 = "reptile_shell"
        $func2 = "reptile_start"
        $func3 = "reptile_module"
        $func4 = "reptile_init"
        $func5 = "reptile_exit"
    condition:
        2 of ($func*)
}

rule Linux_Rootkit_Reptile_c9f8806d {
    meta:
        id = "7A1ihLD3hPzC9MyITLzrYW"
        fingerprint = "v1_sha256_de1f8dc139ca506581119edcbd8d9b19576b0522e86b7f36713538f67a235446"
        version = "1.0"
        date = "2024-11-13"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "parasite_loader"
        $str2 = "parasite_loader/encrypt"
        $str3 = "kmatryoshka.c"
        $str4 = "parasite_loader.mod.c"
        $str5 = "reptile.mod.c"
        $str6 = "parasite_blob"
        $str7 = "name=reptile"
        $loader1 = "loader.c"
        $loader2 = "custom_rol32"
        $loader3 = "do_encode"
        $blob = "_blob"
    condition:
        ((3 of ($str*)) or (all of ($loader*))) and $blob
}

rule Linux_Rootkit_Reptile_eb201301 {
    meta:
        id = "LDtsNnopZd7EHm56nMF1q"
        fingerprint = "v1_sha256_665c791cdcdc3aed7b9dcd6b839b12e3f9a838bef54c698b5d353b44922ea87c"
        version = "1.0"
        date = "2024-11-13"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "Reptile Packet Sender"
        $str2 = "Written by F0rb1dd3n"
        $str3 = "Reptile Wins"
        $str4 = "Written by: F0rb1dd3n"
        $opt1 = "-r Remote port from magic packets (only for tcp/udp)"
        $opt2 = "-x Magic Packet protocol (tcp/icmp/udp)"
        $opt3 = "-s Source IP address to spoof"
        $opt4 = "-q Source port from magic packets (only for tcp/udp)"
        $opt5 = "-l Host to receive the reverse shell"
        $opt6 = "-p Host port to receive the reverse shell"
        $opt7 = "-k Token to trigger the port-knocking"
        $help1 = "Run the listener and send the magic packet"
        $help2 = "Local host to receive the shell"
        $help3 = "Local port to receive the shell"
        $help4 = "Source host on magic packets (spoof)"
        $help5 = "Source port on magic packets (only for TCP/UDP)"
        $help6 = "Remote port (only for TCP/UDP)"
        $help7 = "Protocol to send magic packet (ICMP/TCP/UDP)"
        $rep1 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]"
        $rep2 = "S3cr3tP@ss"
    condition:
        all of ($rep*) or (1 of ($str*) and (4 of ($opt*) or 4 of ($help*)))
}

rule Linux_Rootkit_Reptile_85abf958 {
    meta:
        id = "MCi28mBQ98sliSV6JMmTo"
        fingerprint = "v1_sha256_955dc251eeec64216eafa5c1ff7574e2ee96e72413b689ba147de9fbfc994864"
        version = "1.0"
        date = "2024-11-13"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $byte1 = { C7 06 65 78 65 63 C7 46 04 20 62 61 73 C7 46 08 68 20 2D 2D C7 46 0C 72 63 66 69 C7 46 10 6C 65 20 00 }
        $byte2 = { C7 07 59 6F 75 20 C7 47 04 61 72 65 20 C7 47 08 61 6C 72 65 C7 47 0C 61 64 79 20 C7 47 10 72 6F 6F 74 C7 47 14 21 20 3A 29 C7 47 18 0A 0A 00 00 }
        $byte3 = { C7 47 08 59 6F 75 20 C7 47 0C 68 61 76 65 C7 47 10 20 6E 6F 20 C7 47 14 70 6F 77 65 C7 47 18 72 20 68 65 C7 47 1C 72 65 21 20 C7 47 20 3A 28 20 1B }
        $byte4 = { C7 47 08 59 6F 75 20 C7 47 0C 67 6F 74 20 C7 47 10 73 75 70 65 C7 47 14 72 20 70 6F C7 47 18 77 65 72 73 C7 47 1C 21 1B 5B 30 C7 47 20 30 6D 0A 0A }
        $byte5 = { C7 06 66 69 6C 65 C7 46 04 2D 74 61 6D C7 46 08 70 65 72 69 C7 46 0C 6E 67 00 00 }
        $str1 = "reptile"
        $str2 = "exec bash --rcfi"
    condition:
        any of ($byte*) or all of ($str*)
}

