rule Extra_Data_After_IEND_Chunk
{
    meta:
        description = "[PNG] Check extra data exist after IEND Chunk"
        author = "grm"
        date = "2024-08-02"
    strings:
        // Define the IEND chunk pattern
        $iend = { 49 45 4E 44 AE 42 60 82 }
        // PNG signature
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
    condition:
        $png_header at 0 and  // Ensure it is a PNG file
        $iend and
        filesize > (@iend + 8)
}

rule Text_Chunks_Suspicious_String
{
    meta:
        description = "[PNG] Check String Injection at Text Chunks(tEXt, zTXt, iTXt). If Text Chunks Bigger than 100bytes, Check String's detail"
        author = "grm"
        date = "2024-08-02"
    strings:
        // PNG signature
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }

        // tEXt chunk pattern
        $tEXt_chunk_start = { 74 45 58 74 } // 'tEXt'
        $tEXt_suspicious = /<script.*?>.*?<\/script>|javascript:|eval\(|base64_decode\(|system\(|shell_exec\(|exec\(|document\.cookie|window\.location|window\.open|location\.href|alert\(/i

        // zTXt chunk pattern
        $zTXt_chunk_start = { 7A 54 58 74 } // 'zTXt'
        $zTXt_suspicious = /<script.*?>.*?<\/script>|javascript:|eval\(|base64_decode\(|system\(|shell_exec\(|exec\(|document\.cookie|window\.location|window\.open|location\.href|alert\(/i

        // iTXt chunk pattern
        $iTXt_chunk_start = { 69 54 58 74 } // 'iTXt'
        $iTXt_suspicious = /<script.*?>.*?<\/script>|javascript:|eval\(|base64_decode\(|system\(|shell_exec\(|exec\(|document\.cookie|window\.location|window\.open|location\.href|alert\(/i

    condition:
        $png_header at 0 and  // Ensure it is a PNG file
        (
            // Check if any tEXt, zTXt, or iTXt chunk is present and contains suspicious content
            (
                ($tEXt_chunk_start in (0..filesize) and filesize > 100 and $tEXt_suspicious) or
                ($zTXt_chunk_start in (0..filesize) and filesize > 100 and $zTXt_suspicious) or
                ($iTXt_chunk_start in (0..filesize) and filesize > 100 and $iTXt_suspicious)
            )
        )
}

rule Multiple_IEND_Chunks
{
    meta:
        description = "[PNG] Check if there are more than one IEND (49 45 4E 44 AE 42 60 82) chunks in the file"
        author = "grm"
        date = "2024-08-03"
    strings:
        // Define the IEND chunk pattern
        $iend = { 49 45 4E 44 AE 42 60 82 }
        // PNG signature
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
    condition:
        $png_header at 0 and  // Ensure it is a PNG file
        #iend > 1
}
