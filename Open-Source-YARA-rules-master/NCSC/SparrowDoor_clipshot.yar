import "pe"

rule SparrowDoor_clipshot {
    meta:
        id = "6DodgdhHPvxSWNnxnwYpxw"
        fingerprint = "v1_sha256_7662e3be2752ac82d6cfe4b2e420157e78367c201c25ae34b5d956dc53ba20ae"
        version = "1.0"
        date = "2022-02-28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NCSC"
        description = "The SparrowDoor loader contains a feature it calls clipshot, which logs clipboard data to a file."
        category = "INFO"
        reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
        hash1 = "989b3798841d06e286eb083132242749c80fdd4d"

strings:
$exsting_cmp = {8B 1E 3B 19 75 ?? 83 E8 04 83 C1 04 83 C6 04 83 F8 04} // comparison routine for previous clipboard data
$time_format_string = "%d/%d/%d %d:%d" ascii
$cre_fil_args = {6A 00 68 80 00 00 00 6A 04 6A 00 6A 02 68 00 00 00 40 52}
condition:
(uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and
all of them and (pe.imports("User32.dll","OpenClipboard") and
pe.imports("User32.dll","GetClipboardData") and
pe.imports("Kernel32.dll","GetLocalTime") and
pe.imports("Kernel32.dll","GlobalSize"))
}
