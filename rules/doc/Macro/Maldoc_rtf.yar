rule Detect_RTF_Embedded_Objects
{
    meta:
        description = "Detects embedded objects in RTF files"
        author = "Your Name"
        date = "2024-06-25"
        atk_type = "Macro"

    strings:
        $rtf_header = {7B 5C 72 74 66}
        $embedded_object = {6F 62 6A 65 6D 62 65 64}

    condition:
        $rtf_header at 0 and $embedded_object
}

rule Detect_RTF_External_Links
{
    meta:
        description = "Detects external links in RTF files"
        author = "Your Name"
        date = "2024-06-25"
        atk_type = "Macro"

    strings:
        $rtf_header = {7B 5C 72 74 66}
        $external_link = /http[s]?:\/\//

    condition:
        $rtf_header at 0 and $external_link
}

rule Detect_RTF_Suspicious_Control_Words
{
    meta:
      atk_type = "Macro"
        description = "Detects suspicious control words in RTF files"
        author = "Your Name"
        date = "2024-06-25"

    strings:
        $rtf_header = {7B 5C 72 74 66}
        $suspicious_ctrl = /\\bin/

    condition:
        $rtf_header at 0 and $suspicious_ctrl
}


