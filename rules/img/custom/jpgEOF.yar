rule Extra_Data_After_EOF
{
    meta:
        description = "[JPEG] Check for extra data after a single EOF marker"
        author = "grm"
        date = "2024-08-03"

    strings:
        $eoi = { FF D9 }
        $jpeg_header = { FF D8 }  // JPEG 파일의 시작 시그니처

    condition:
        $jpeg_header at 0 and  // 파일이 JPEG 형식인지 확인
        $eoi and
        filesize > (@eoi + 2)
}

rule Multiple_EOF
{
    meta:
        description = "[JPEG] Check if there are more than one EOF (FF D9) markers in the file"
        author = "grm"
        date = "2024-08-03"

    strings:
        $eoi = { FF D9 }
        $jpeg_header = { FF D8 }  // JPEG 파일의 시작 시그니처

    condition:
        $jpeg_header at 0 and  // 파일이 JPEG 형식인지 확인
        #eoi > 1  // EOF 마커가 1개 초과인지 확인
}

// 음, 이건 좀 조건 추가가 필요할듯?
