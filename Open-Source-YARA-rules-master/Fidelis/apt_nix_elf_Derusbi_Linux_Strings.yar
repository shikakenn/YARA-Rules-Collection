rule apt_nix_elf_Derusbi_Linux_Strings
{
    meta:
        id = "imzMufYWA1wWVI70vZH2T"
        fingerprint = "v1_sha256_b54b406a562247d4c3d4a9c4d1b7584bdcecfe5b6c76867c04770e016eeb8c9a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Fidelis Cybersecurity"
        description = "NA"
        category = "INFO"
        reference = "https://www.fidelissecurity.com/resources/turbo-campaign-featuring-derusbi-64-bit-linux"

    strings:
        $a1 = "loadso" wide ascii fullword
            $a2 = "\nuname -a\n\n" wide ascii
            $a3 = "/dev/shm/.x11.id" wide ascii
            $a4 = "LxMain64" wide ascii nocase
            $a5 = "# \\u@\\h:\\w \\$ " wide ascii
            $b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
            $b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
            $b3 = "ret %d" wide fullword
            $b4 = "uname -a\n\n" wide ascii
            $b5 = "/proc/%u/cmdline" wide ascii
            $b6 = "/proc/self/exe" wide ascii
            $b7 = "cp -a %s %s" wide ascii
            $c1 = "/dev/pts/4" wide ascii fullword
            $c2 = "/tmp/1408.log" wide ascii fullword
    condition:
        uint32(0) == 0x464C457F and
        ((1 of ($a*) and 4 of ($b*)) or
        (1 of ($a*) and 1 of ($c*)) or
        2 of ($a*) or
        all of ($b*))
}

