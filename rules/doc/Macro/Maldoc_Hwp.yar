rule Detect_HWP_Embedded_Executable
{
    meta:
        description = "Detects embedded executables in HWP files"
        author = "Your Name"
        date = "2024-06-25"
        atk_type = "Macro"

    strings:
        $hwp_header = {48 57 50 20 44 6F 63 75 6D 65 6E 74 20 46 69 6C 65}
        $exe_pattern = {4D 5A}

    condition:
        $hwp_header at 0 and $exe_pattern
}

rule Detect_HWP_Suspicious_Scripts
{
    meta:
        description = "Detects suspicious scripts in HWP files"
        author = "Your Name"
        date = "2024-06-25"
        atk_type = "Macro"

    strings:
        $hwp_header = {48 57 50 20 44 6F 63 75 6D 65 6E 74 20 46 69 6C 65}
        $script_signature = {42 49 4E 44 41 54 41}

    condition:
        $hwp_header at 0 and $script_signature
}

rule Detect_HWP_Unusual_Metadata
{
    meta:
      atk_type = "Macro"
        description = "Detects unusual metadata in HWP files"
        author = "Your Name"
        date = "2024-06-25"

    strings:
        $hwp_header = {48 57 50 20 44 6F 63 75 6D 65 6E 74 20 46 69 6C 65}
        $metadata_pattern = {44 4F 43 49 4E 46 4F}

    condition:
        $hwp_header at 0 and $metadata_pattern
}
