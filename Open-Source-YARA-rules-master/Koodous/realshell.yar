rule dropper:realshell {
    meta:
        id = "10S0SE2IzsPZz7oqoqwA41"
        fingerprint = "v1_sha256_018a0080bed283540a74c32069cf6d23574cafc200d31b43b3931d4c9b86eddb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "HTTPS://BLOG.MALWAREBYTES.ORG/MOBILE-2/2015/06/COMPLEX-METHOD-OF-OBFUSCATION-FOUND-IN-DROPPER-REALSHELL/"
        author = "Undefined"
        description = "NA"
        category = "INFO"

    strings:
        $a = "hexKey:"
        $b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
    
    condition:
        any of them
}
