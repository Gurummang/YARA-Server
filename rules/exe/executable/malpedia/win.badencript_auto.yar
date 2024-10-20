rule win_badencript_auto {

    meta:
        atk_type = "win.badencript."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.badencript."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badencript"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 8bfe a1???????? 897de0 394508 7c1f 3934bd48414100 }
            // n = 6, score = 100
            //   8bfe                 | mov                 edi, esi
            //   a1????????           |                     
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   394508               | cmp                 dword ptr [ebp + 8], eax
            //   7c1f                 | jl                  0x21
            //   3934bd48414100       | cmp                 dword ptr [edi*4 + 0x414148], esi

        $sequence_1 = { 8a07 8b0c9548414100 8844192e 8b049548414100 }
            // n = 4, score = 100
            //   8a07                 | mov                 al, byte ptr [edi]
            //   8b0c9548414100       | mov                 ecx, dword ptr [edx*4 + 0x414148]
            //   8844192e             | mov                 byte ptr [ecx + ebx + 0x2e], al
            //   8b049548414100       | mov                 eax, dword ptr [edx*4 + 0x414148]

        $sequence_2 = { 6af6 ff15???????? 8b04bd48414100 834c0318ff 33c0 eb16 e8???????? }
            // n = 7, score = 100
            //   6af6                 | push                -0xa
            //   ff15????????         |                     
            //   8b04bd48414100       | mov                 eax, dword ptr [edi*4 + 0x414148]
            //   834c0318ff           | or                  dword ptr [ebx + eax + 0x18], 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   eb16                 | jmp                 0x18
            //   e8????????           |                     

        $sequence_3 = { 53 ffd7 83ee01 75eb 8b4dfc 33c0 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   ffd7                 | call                edi
            //   83ee01               | sub                 esi, 1
            //   75eb                 | jne                 0xffffffed
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 8b049d48414100 8945d4 8955e8 8a5c1029 80fb02 7405 80fb01 }
            // n = 7, score = 100
            //   8b049d48414100       | mov                 eax, dword ptr [ebx*4 + 0x414148]
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   8a5c1029             | mov                 bl, byte ptr [eax + edx + 0x29]
            //   80fb02               | cmp                 bl, 2
            //   7405                 | je                  7
            //   80fb01               | cmp                 bl, 1

        $sequence_5 = { 660fd60f 8d7f08 8b048d04b54000 ffe0 f7c703000000 }
            // n = 5, score = 100
            //   660fd60f             | movq                qword ptr [edi], xmm1
            //   8d7f08               | lea                 edi, [edi + 8]
            //   8b048d04b54000       | mov                 eax, dword ptr [ecx*4 + 0x40b504]
            //   ffe0                 | jmp                 eax
            //   f7c703000000         | test                edi, 3

        $sequence_6 = { 8b049548414100 f644082801 740b 56 e8???????? 59 }
            // n = 6, score = 100
            //   8b049548414100       | mov                 eax, dword ptr [edx*4 + 0x414148]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1
            //   740b                 | je                  0xd
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_7 = { 0f859b010000 c745e0980f4100 8b4508 8bcf 8b7510 c745dc01000000 dd00 }
            // n = 7, score = 100
            //   0f859b010000         | jne                 0x1a1
            //   c745e0980f4100       | mov                 dword ptr [ebp - 0x20], 0x410f98
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bcf                 | mov                 ecx, edi
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   c745dc01000000       | mov                 dword ptr [ebp - 0x24], 1
            //   dd00                 | fld                 qword ptr [eax]

        $sequence_8 = { 58 6bc000 c7809439410002000000 6a04 }
            // n = 4, score = 100
            //   58                   | pop                 eax
            //   6bc000               | imul                eax, eax, 0
            //   c7809439410002000000     | mov    dword ptr [eax + 0x413994], 2
            //   6a04                 | push                4

        $sequence_9 = { 50 8b04bd48414100 ff743018 ff15???????? 85c0 0f95c0 5f }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b04bd48414100       | mov                 eax, dword ptr [edi*4 + 0x414148]
            //   ff743018             | push                dword ptr [eax + esi + 0x18]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f95c0               | setne               al
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 335872
}