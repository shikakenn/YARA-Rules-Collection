rule Linux_Trojan_BPFDoor_59e029c3 {
    meta:
        id = "3O5elyypM97rlE0KSDe1PM"
        fingerprint = "v1_sha256_64620a3404b331855d0b8018c1626c88cb28380785beac1a391613ae8dc1b1bf"
        version = "1.0"
        date = "2022-05-10"
        modified = "2022-05-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        threat_name = "Linux.Trojan.BPFDoor"
        reference_sample = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $a2 = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d" ascii fullword
        $a3 = "avahi-daemon: chroot helper" ascii fullword
        $a4 = "/sbin/mingetty /dev/tty6" ascii fullword
        $a5 = "ttcompat" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_0f768f60 {
    meta:
        id = "1rQ52WnPg5GbDsPNOgbztV"
        fingerprint = "v1_sha256_1aaa74c2d8fbb230cbfc0e08fd6865b5f7e90e4abcdb97121e52afb7569b2dbc"
        version = "1.0"
        date = "2022-05-10"
        modified = "2022-05-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        threat_name = "Linux.Trojan.BPFDoor"
        reference_sample = "3a1b174f0c19c28f71e1babde01982c56d38d3672ea14d47c35ae3062e49b155"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $a2 = "/sbin/mingetty /dev/tty7" ascii fullword
        $a3 = "pickup -l -t fifo -u" ascii fullword
        $a4 = "kdmtmpflush" ascii fullword
        $a5 = "avahi-daemon: chroot helper" ascii fullword
        $a6 = "/sbin/auditd -n" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_8453771b {
    meta:
        id = "6Yr21DLv2I3LiFI1qiIf8L"
        fingerprint = "v1_sha256_546e5c56ceb6b99db14dc225a2ec4872cb54859a0f2f6ad520d4f446793e031e"
        version = "1.0"
        date = "2022-05-10"
        modified = "2022-05-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        threat_name = "Linux.Trojan.BPFDoor"
        reference_sample = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "[-] Spawn shell failed." ascii fullword
        $a2 = "[+] Packet Successfuly Sending %d Size." ascii fullword
        $a3 = "[+] Monitor packet send." ascii fullword
        $a4 = "[+] Using port %d"
        $a5 = "decrypt_ctx" ascii fullword
        $a6 = "getshell" ascii fullword
        $a7 = "getpassw" ascii fullword
        $a8 = "export %s=%s" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_f690fe3b {
    meta:
        id = "yPGBFpEYCvGbd8dsbg9eR"
        fingerprint = "v1_sha256_35c6be75348a30f415a1a4bb94ae7e3a2f49f54a0fb3ddc4bae1aa3e03c1a909"
        version = "1.0"
        date = "2022-05-10"
        modified = "2022-05-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        threat_name = "Linux.Trojan.BPFDoor"
        reference_sample = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 45 D8 0F B6 10 0F B6 45 FF 48 03 45 F0 0F B6 00 8D 04 02 00 }
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_1a7d804b {
    meta:
        id = "6iyku2ngtm1UIgbbe3t3l5"
        fingerprint = "v1_sha256_b0c4b168d92947e599e8c74d0ae6a91766c8a034c34e9c07e2472620c9b61037"
        version = "1.0"
        date = "2022-05-10"
        modified = "2022-05-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        threat_name = "Linux.Trojan.BPFDoor"
        reference_sample = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "getshell" ascii fullword
        $a2 = "/sbin/agetty --noclear tty1 linux" ascii fullword
        $a3 = "packet_loop" ascii fullword
        $a4 = "godpid" ascii fullword
        $a5 = "ttcompat" ascii fullword
        $a6 = "decrypt_ctx" ascii fullword
        $a7 = "rc4_init" ascii fullword
        $b1 = { D0 48 89 45 F8 48 8B 45 F8 0F B6 40 0C C0 E8 04 0F B6 C0 C1 }
    condition:
        all of ($a*) or 1 of ($b*)
}

rule Linux_Trojan_BPFDoor_e14b0b79 {
    meta:
        id = "4ySn3srAgEDx6fD20vK3X5"
        fingerprint = "v1_sha256_7cdf111ae253bffef7243ad3722f1a79f81f45d80f938f9542af8e056f75d3fc"
        version = "1.0"
        date = "2022-05-10"
        modified = "2022-05-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        threat_name = "Linux.Trojan.BPFDoor"
        reference_sample = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "getpassw" ascii fullword
        $a2 = "(udp[8:2]=0x7255) or (icmp[8:2]=0x7255) or (tcp[((tcp[12]&0xf0)>>2):2]=0x5293)" ascii fullword
        $a3 = "/var/run/haldrund.pid" ascii fullword
        $a4 = "Couldn't install filter %s: %s" ascii fullword
        $a5 = "godpid" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_f1cd26ad {
    meta:
        id = "gdIgh19swO16PIrx0FyfO"
        fingerprint = "v1_sha256_ad3e130d5a1203c55b5c8d369c7d9989f66f76c9bd57e2314a30f4c931e4b98d"
        version = "1.0"
        date = "2023-05-11"
        modified = "2023-05-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        threat_name = "Linux.Trojan.BPFDoor"
        reference_sample = "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $magic_bytes_check = { 0F C8 0F CA 3D 9F CD 30 44 ?? ?? ?? ?? ?? ?? 81 FA 66 27 14 5E }
        $seq_binary = { 48 C1 E6 08 48 C1 E0 14 48 01 F0 48 01 C8 89 E9 48 C1 E8 20 29 C1 D1 E9 01 C8 C1 E8 0B 83 C0 01 89 C6 C1 E6 0C }
        $signals_setup = { BE 01 00 00 00 BF 02 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 01 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 03 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 0D 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 16 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 15 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 11 00 00 00 ?? ?? ?? ?? ?? BF 0A 00 00 00 }
    condition:
        ($magic_bytes_check and $seq_binary) or $signals_setup
}

