rule cryptomix_packer
{
    meta:
        id = "3Tlx9cFbcOildFWMFf75d4"
        fingerprint = "v1_sha256_71510e97e19cc44f4bbdcfa254bf509c0099a2272a61f8b4b980d1c21e2d5217"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "msm"
        description = "NA"
        category = "INFO"
        reference = "https://www.cert.pl/en/news/single/technical-analysis-of-cryptomixcryptfile2-ransomware/"

    strings:
       $old_real_main = {8B [5] 8B [5] 03 ?? 89 ?? FC FF 55 FC}
       $old_crypto_ops = {83 ?? 1F 83 ?? 60}
       $old_crypto_xor = {8A 90 [4] 30 14 0E}  // extract xor key from this

       $new_crypto_ops = {03 85 [4] 88 10 EB ??}
       $new_crypto_xor = {A1 [4] 89 45 ??}  // extract xor key from this

    condition:
       2 of them
}
