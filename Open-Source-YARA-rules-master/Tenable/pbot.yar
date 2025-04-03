rule pbot
{
    meta:
        id = "3sfQiUVEL4rkCoZMO2NANI"
        fingerprint = "v1_sha256_2cfeba06becd3f43ab8e43524b440dc43e987b2808add10356bb96c8581b08da"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "PHP IRC Bot"
        category = "INFO"
        hash = "cd62b4c32f0327d06dd99648e44c85560416a40f6734429d3e89a4c5250fd28e"
        hash = "80fb661aac9fcfbb5ae356c5adc7d403bf15da9432b5e33fbbed938c42fdde3c"
        hash = "6873bcc7f3971c42564a5fb72d5963b1660c6ff53409e496695523c1115e9734"
        family = "Backdoor.PHP.Pbot"
        filetype = "PHP"

    strings:
        $class = "class pBot" ascii
        $start = "function start(" ascii
        $ping = "PING" ascii
        $pong = "PONG" ascii

    condition:
        all of them
}
