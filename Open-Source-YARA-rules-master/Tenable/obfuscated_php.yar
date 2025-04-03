rule eval_statement
{
    meta:
        id = "5NxwxBOWC22Us3MWGlazRv"
        fingerprint = "v1_sha256_f8df89706d6a637e456402db0cb544aa38f8632532ff1d32fdb151db62ad3122"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Obfuscated PHP eval statements"
        category = "INFO"
        hash = "9da32d35a28d2f8481a4e3263e2f0bb3836b6aebeacf53cd37f2fe24a769ff52"
        hash = "8c1115d866f9f645788f3689dff9a5bacfbee1df51058b4161819c750cf7c4a1"
        hash = "14083cf438605d38a206be33542c7a4d48fb67c8ca0cfc165fa5f279a6d55361"
        family = "PHP.Obfuscated"
        filetype = "PHP"

    strings:
        $obf = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/

    condition:
        all of them
}

rule hardcoded_urldecode
{
    meta:
        id = "5bI0bmATfIi9I2B3epyM8T"
        fingerprint = "v1_sha256_7fc3f6d301f0482d81378413301f01b4c1894f9d635333b24b50eb9c8f21bb56"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "PHP with hard coded urldecode call"
        category = "INFO"
        hash = "79b22d7dbf49d8cfdc564936c8a6a1e2"
        hash = "38dc8383da0859dca82cf0c943dbf16d"
        family = "PHP.Obfuscated"
        filetype = "PHP"

    strings:
        $obf = /urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)/

    condition:
        all of them
}

rule chr_obfuscation
{
    meta:
        id = "7IyRh1xT9EhU0tD24Pdojc"
        fingerprint = "v1_sha256_90ae182c069a7e4b0a04b66e82e725d72d02a713b5dec5b4c6f2106d808ea4e5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "PHP with string building using hard coded values in chr()"
        category = "INFO"
        hash = "d771409e152d0fabae45ea192076d45e"
        hash = "543624bec87272974384c8ab77f2357a"
        hash = "cf2ab009cbd2576a806bfefb74906fdf"
        family = "PHP.Obfuscated"
        filetype = "PHP"

    strings:
        $obf = /\$[^=]+=[\t ]*(chr\([0-9]+\)\.?){2,}/

    condition:
        all of them
}
