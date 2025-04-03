rule apt_nix_elf_Derusbi_Linux_SharedMemCreation
{
    meta:
        id = "5SDtjUWbZe401Tc4iBbiQe"
        fingerprint = "v1_sha256_ffb46c0300461c9ba09fac7cecbdb57bcc8390fdc50331ec306bab3ea600a3b8"
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
        $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }
    condition:
        (uint32(0) == 0x464C457F) and (any of them)
}



