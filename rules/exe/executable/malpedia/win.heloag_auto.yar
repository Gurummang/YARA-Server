rule win_heloag_auto {

    meta:
        atk_type = "win.heloag."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.heloag."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.heloag"
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
        $sequence_0 = { 66ab aa 83c9ff 8bfe 33c0 }
            // n = 5, score = 300
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   83c9ff               | or                  ecx, 0xffffffff
            //   8bfe                 | mov                 edi, esi
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 8bf7 8bfa 8a15???????? c1e902 f3a5 8bc8 }
            // n = 6, score = 300
            //   8bf7                 | mov                 esi, edi
            //   8bfa                 | mov                 edi, edx
            //   8a15????????         |                     
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax

        $sequence_2 = { 8d4dbc 51 ffd7 8b45c4 b919000000 }
            // n = 5, score = 300
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   b919000000           | mov                 ecx, 0x19

        $sequence_3 = { 8b0d???????? 51 e8???????? 6a14 e8???????? 8bf0 83c408 }
            // n = 7, score = 300
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   e8????????           |                     
            //   6a14                 | push                0x14
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c408               | add                 esp, 8

        $sequence_4 = { f3a4 a2???????? a2???????? a3???????? }
            // n = 4, score = 300
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   a2????????           |                     
            //   a2????????           |                     
            //   a3????????           |                     

        $sequence_5 = { 7cc4 8b45fc 8b0d???????? 40 }
            // n = 4, score = 300
            //   7cc4                 | jl                  0xffffffc6
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b0d????????         |                     
            //   40                   | inc                 eax

        $sequence_6 = { 6a00 6a00 ffd0 33c9 a3???????? 85c0 0f95c1 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ffd0                 | call                eax
            //   33c9                 | xor                 ecx, ecx
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   0f95c1               | setne               cl

        $sequence_7 = { 8d8dacfdffff 68???????? 51 e8???????? 8b55b4 83c41c 66c745b80200 }
            // n = 7, score = 300
            //   8d8dacfdffff         | lea                 ecx, [ebp - 0x254]
            //   68????????           |                     
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]
            //   83c41c               | add                 esp, 0x1c
            //   66c745b80200         | mov                 word ptr [ebp - 0x48], 2

        $sequence_8 = { 8b4e0c 3bcd 8b07 89442410 7464 }
            // n = 5, score = 200
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   3bcd                 | cmp                 ecx, ebp
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   7464                 | je                  0x66

        $sequence_9 = { 894b0c 8a48ff fec1 8848ff eb3c 6a01 55 }
            // n = 7, score = 200
            //   894b0c               | mov                 dword ptr [ebx + 0xc], ecx
            //   8a48ff               | mov                 cl, byte ptr [eax - 1]
            //   fec1                 | inc                 cl
            //   8848ff               | mov                 byte ptr [eax - 1], cl
            //   eb3c                 | jmp                 0x3e
            //   6a01                 | push                1
            //   55                   | push                ebp

        $sequence_10 = { 8b4108 50 e8???????? 6a01 }
            // n = 4, score = 200
            //   8b4108               | mov                 eax, dword ptr [ecx + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a01                 | push                1

        $sequence_11 = { 85c0 7505 a1???????? 8b4c242c }
            // n = 4, score = 200
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   a1????????           |                     
            //   8b4c242c             | mov                 ecx, dword ptr [esp + 0x2c]

        $sequence_12 = { 51 53 68???????? 8d4c2420 ff15???????? }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   68????????           |                     
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   ff15????????         |                     

        $sequence_13 = { 8a442413 6a00 8bce 8806 ff15???????? }
            // n = 5, score = 200
            //   8a442413             | mov                 al, byte ptr [esp + 0x13]
            //   6a00                 | push                0
            //   8bce                 | mov                 ecx, esi
            //   8806                 | mov                 byte ptr [esi], al
            //   ff15????????         |                     

        $sequence_14 = { 8b11 8bcf 52 6a00 50 ff15???????? }
            // n = 6, score = 200
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8bcf                 | mov                 ecx, edi
            //   52                   | push                edx
            //   6a00                 | push                0
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_15 = { a1???????? 894304 8b5608 895308 8b4e0c 894b0c }
            // n = 6, score = 200
            //   a1????????           |                     
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   8b5608               | mov                 edx, dword ptr [esi + 8]
            //   895308               | mov                 dword ptr [ebx + 8], edx
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   894b0c               | mov                 dword ptr [ebx + 0xc], ecx

    condition:
        7 of them and filesize < 401408
}