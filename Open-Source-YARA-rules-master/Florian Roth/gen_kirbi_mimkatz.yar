/*
    Yara Rule Set
    Author: Didier Stevens
    Date: 2016-08-13
    Identifier: KiRBi ticket for mimikatz
*/

/* Rule Set ----------------------------------------------------------------- */

rule mimikatz_kirbi_ticket
{
    meta:
        id = "2P5MuHt4MVFr0KA9syS7Rr"
        fingerprint = "v1_sha256_2a62c24954d64346e419985ef5bf2b357b2aee41ac6b33d379dbd65cf5c9f92b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Benjamin DELPY (gentilkiwi); Didier Stevens"
        description = "KiRBi ticket for mimikatz"
        category = "INFO"

    strings:
        $asn1			= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
        $asn1_84		= { 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }

    condition:
        $asn1 at 0 or $asn1_84 at 0
}
