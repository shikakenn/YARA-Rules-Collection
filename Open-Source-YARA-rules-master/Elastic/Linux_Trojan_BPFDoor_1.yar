rule Linux_Trojan_BPFDoor_1 {

    meta:
        id = "JygS9PDPLQJQ0DujJb5Pt"
        fingerprint = "v1_sha256_64620a3404b331855d0b8018c1626c88cb28380785beac1a391613ae8dc1b1bf"
        version = "1.0"
        date = "2022-05-10"
        modified = "2022-05-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Detects BPFDoor malware."
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        Author = "Elastic Security"
        os = "Linux"
        arch = "x86"
        category_type = "Trojan"
        family = "BPFDoor"
        threat_name = "Linux.Trojan.BPFDoor"
        reference_sample = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"

    strings:
        $a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $a2 = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d" ascii fullword
        $a3 = "avahi-daemon: chroot helper" ascii fullword
        $a4 = "/sbin/mingetty /dev/tty6" ascii fullword
        $a5 = "ttcompat" ascii fullword
    condition:
        all of them
}
