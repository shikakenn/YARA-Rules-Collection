rule Check_VBox_VideoDrivers
{
    meta:
        id = "5jcyIzEGBP8A43PitIOnxg"
        fingerprint = "v1_sha256_7601e8d1eebf3a8aca4d6fae7f70855a5615ee3c7d1010ff9d5dbd5ac662ec59"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for reg keys of Vbox video drivers"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "VideoBiosVersion" wide nocase ascii
        $data = "VIRTUALBOX" nocase wide ascii
    condition:
        all of them
}
