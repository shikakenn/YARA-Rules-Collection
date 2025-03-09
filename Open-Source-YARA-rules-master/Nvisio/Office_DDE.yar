
// YARA rules Office DDE
// NVISO 2017/10/10 - 2017/10/12
// https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/
  
rule Office_DDEAUTO_field {
    meta:
        id = "6uoSE6Zvv3YA6tqKarXauH"
        fingerprint = "v1_sha256_998f3b1445f515c95cf32c68d1ffda5cabb5487986c4f373845e996098f52aca"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"

  strings:
    $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
  condition:
    $a
}
  
rule Office_DDE_field {
    meta:
        id = "1iFqbiXMtKoHALgOJWMAl8"
        fingerprint = "v1_sha256_f1394f5ce8e9bbad913a153ecb46b65e26db610c0a53a253b1d12175a7a16f3d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"

  strings:
    $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
  condition:
    $a
}
 
rule Office_OLE_DDEAUTO {
    meta:
        id = "69XeKxTmDNiJ9hpwjxRhSU"
        fingerprint = "v1_sha256_831a0072c1bfddb26a07c772a8f9fd80194757d436a14e31a16448bf98d555f4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"

  strings:
    $a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase
  condition:
    uint32be(0) == 0xD0CF11E0 and $a
}
 
rule Office_OLE_DDE {
    meta:
        id = "449rgcWXnMdbSKgwnEVxO"
        fingerprint = "v1_sha256_a14cd720c29b2ba319f512225dea5f5127ca6f5cb0deeaf1cb48b5203a876a58"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"

  strings:
    $a = /\x13\s*DDE\b[^\x14]+/ nocase
  condition:
    uint32be(0) == 0xD0CF11E0 and $a
}
