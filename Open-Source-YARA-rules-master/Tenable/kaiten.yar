import "elf"

rule Kaiten
{
    meta:
        id = "4BmPnQ11ZzNeViO0yv6boS"
        fingerprint = "v1_sha256_3fb57c12eeb50b63fb4a89807eee7981be6a2464e5d9c21d79edb33516bae4c9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Linux IRC DDoS Malware"
        category = "INFO"
        hash = "6b5386d96b90a4cb811c5ddd6f35f6b0d4c65c69c8160216077e7a0f43a8888d"
        hash = "965a9594ef80e7134e1a9e5a4cce0a3dce98636107d1f6410224386dfccb9d5b"
        hash = "2c772242de272bff1bb940b0687445739ec544aceec1bc5591a374a57cd652b5"
        family = "Linux.Backdoor.Kaiten"
        filetype = "ELF"

    strings:
        $irc = /(PING)|(PONG)|(NOTICE)|(PRIVMSG)/
        $kill = "Killing pid %d" nocase
        $subnet = "What kind of subnet address is that" nocase
        $version = /(Helel mod)|(Kaiten wa goraku)/
        $flood = "UDP <target> <port> <secs>" nocase

    condition:
        elf.type == elf.ET_EXEC and $irc and
        2 of ($kill, $subnet, $version, $flood)
}
