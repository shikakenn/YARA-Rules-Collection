import "pe"

rule research_pe_signed_outside_timestamp {
    meta:
        id = "7acu9N0Oc0s9GBDudlaUPZ"
        fingerprint = "v1_sha256_323970f2322f8eb1059fb54c5f1bdb582970229b4a444f67cff794877fec19b2"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "PE linker timestamp is outside the Authenticode validity period"
        category = "INFO"

  strings:
    $mz = "MZ"

  condition:
    $mz at 0 and pe.number_of_signatures > 0 and not for all i in (0..pe.number_of_signatures - 1):
    (
      pe.signatures[i].valid_on(pe.timestamp)
    )
}
