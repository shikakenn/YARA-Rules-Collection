 rule apt_all_JavaScript_ScanboxFramework_obfuscated

{
    meta:
        id = "4iMDhlVK3kbeD3KqA3m9pJ"
        fingerprint = "v1_sha256_36168a3fc5898bbe9b3dff96e22addfe551e687cec3f7afa77df5bce7de7db69"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Fidelis Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.fidelissecurity.com/TradeSecret"

           strings:

                  $sa1 = /(var|new|return)\s[_\$]+\s?/

                  $sa2 = "function"

                  $sa3 = "toString"

                  $sa4 = "toUpperCase"

                  $sa5 = "arguments.length"

                  $sa6 = "return"

                  $sa7 = "while"

                  $sa8 = "unescape("

                  $sa9 = "365*10*24*60*60*1000"

                  $sa10 = ">> 2"

                  $sa11 = "& 3) << 4"

                  $sa12 = "& 15) << 2"

                  $sa13 = ">> 6) | 192"

                  $sa14 = "& 63) | 128"

                  $sa15 = ">> 12) | 224"

                  condition:

                  all of them

}
