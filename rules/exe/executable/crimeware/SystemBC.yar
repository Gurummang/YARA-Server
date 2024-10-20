rule SystemBC_Socks
{
    meta:
        atk_type = "SystemBC_Socks"
        id = "6zIY8rmud3SM6CWLPwxaky"
        fingerprint = "09472e26edd142cd68a602f1b6e31abbd4c8ec90c36d355a01692d44ef02a14f"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SystemBC RAT, Socks proxy version."
        category = "MALWARE"
        malware = "SYSTEMBC"
        malware_type = "RAT"

    strings:
        $code1 = { 68 10 27 00 00 e8 ?? ?? ?? ?? 8d ?? 72 fe ff ff 50 68 02 02 00 00 e8 ?? ?? 
    ?? ?? 85 c0 75 ?? c7 8? ?? ?? ?? ?? ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 6a ff 68 ?? ?? 
    ?? ?? e8 ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 e8 ?? ?? ?? ?? 89 8? ?? ?? ?? ?? ff b? ?? 
    ?? ?? ?? ff b? ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 81 b? ?? ?? ?? ?? ?? ?? ?? ?? 
    75 ?? c7 8? ?? ?? ?? ?? ?? ?? ?? ?? eb ?? }
        $code2 = { 55 8b ec 81 c4 d0 fe ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 
    ?? ?? ?? ?? 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 4? ?? 6a 04 ff 7? ?? 8d ?? fc 50 e8 
    ?? ?? ?? ?? c7 8? ?? ?? ?? ?? 01 00 00 00 6a 04 8d ?? d4 fe ff ff 50 6a 01 6a 06 ff 
    7? ?? e8 ?? ?? ?? ?? 8d ?? d8 fe ff ff 50 6a ff ff 7? ?? e8 ?? ?? ?? ?? 6a 02 8d ?? 
    d8 fe ff ff 50 e8 ?? ?? ?? ?? 89 4? ?? 8b 4? ?? 3d 00 00 01 00 76 ?? 50 e8 ?? ?? ?? ?? }

    condition:
        any of them
}

rule SystemBC_Config
{
    meta:
        atk_type = "SystemBC_Config"
        id = "70WDDM1D5xtPBqsUdBiPTK"
        fingerprint = "8de029e2f4fc81742a3e04976a58360e403ce5737098c14e0a007c306a1e0f01"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SystemBC RAT, decrypted config."
        category = "MALWARE"
        malware_type = "RAT"

    strings:
        $ = "BEGINDATA" ascii wide fullword
        $ = "HOST1:" ascii wide fullword
        $ = "HOST2:" ascii wide fullword
        $ = "PORT1:" ascii wide fullword
        $ = "TOR:" ascii wide fullword
        $ = "-WindowStyle Hidden -ep bypass -file" ascii wide

    condition:
        3 of them
}