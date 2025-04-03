rule W97M_Vawtrak_dropper
{
    meta:
        id = "FCWvXsEWzVV89IKP5BoKA"
        fingerprint = "v1_sha256_4b1e1ba92cf343d7e34bbb85ec98756541920dc19ae1673674a32c5f6e9119a9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee"
        description = "W97M_Vawtrak_Dropper"
        category = "INFO"
        reference = "https://securingtomorrow.mcafee.com/mcafee-labs/w97m-downloader-serving-vawtrak/"

strings:
$asterismal="asterismal"
$bootlicking="bootlicking"
$shell="WScript.Shell"
$temp="%temp%"
$oxygon="oxygon.exe"
$saxhorn = "saxhorn"
$fire = "Fire"
$bin= "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e"

condition:
all of them
}
