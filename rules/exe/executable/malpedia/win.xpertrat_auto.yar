rule win_xpertrat_auto {

    meta:
        atk_type = "win.xpertrat."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.xpertrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xpertrat"
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
        $sequence_0 = { 0870ff 0d80000700 0474 ff0478 }
            // n = 4, score = 200
            //   0870ff               | or                  byte ptr [eax - 1], dh
            //   0d80000700           | or                  eax, 0x70080
            //   0474                 | add                 al, 0x74
            //   ff0478               | inc                 dword ptr [eax + edi*2]

        $sequence_1 = { ff0a 250004003c 6c 70ff 0808 }
            // n = 5, score = 200
            //   ff0a                 | dec                 dword ptr [edx]
            //   250004003c           | and                 eax, 0x3c000400
            //   6c                   | insb                byte ptr es:[edi], dx
            //   70ff                 | jo                  1
            //   0808                 | or                  byte ptr [eax], cl

        $sequence_2 = { ff05???????? 000d???????? 0878ff 0d98000700 6e 74ff }
            // n = 6, score = 200
            //   ff05????????         |                     
            //   000d????????         |                     
            //   0878ff               | or                  byte ptr [eax - 1], bh
            //   0d98000700           | or                  eax, 0x70098
            //   6e                   | outsb               dx, byte ptr [esi]
            //   74ff                 | je                  1

        $sequence_3 = { 0808 008f38001b26 001b 0d002a2364 ff08 }
            // n = 5, score = 200
            //   0808                 | or                  byte ptr [eax], cl
            //   008f38001b26         | add                 byte ptr [edi + 0x261b0038], cl
            //   001b                 | add                 byte ptr [ebx], bl
            //   0d002a2364           | or                  eax, 0x64232a00
            //   ff08                 | dec                 dword ptr [eax]

        $sequence_4 = { ff4d40 ff08 40 0430 ff0a 4c 000c00 }
            // n = 7, score = 200
            //   ff4d40               | dec                 dword ptr [ebp + 0x40]
            //   ff08                 | dec                 dword ptr [eax]
            //   40                   | inc                 eax
            //   0430                 | add                 al, 0x30
            //   ff0a                 | dec                 dword ptr [edx]
            //   4c                   | dec                 esp
            //   000c00               | add                 byte ptr [eax + eax], cl

        $sequence_5 = { 0000 00a1cc004400 0bc0 7402 ffe0 68???????? }
            // n = 6, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   00a1cc004400         | add                 byte ptr [ecx + 0x4400cc], ah
            //   0bc0                 | or                  eax, eax
            //   7402                 | je                  4
            //   ffe0                 | jmp                 eax
            //   68????????           |                     

        $sequence_6 = { 0808 008a3800cc1c 5e 006c70ff 0808 }
            // n = 5, score = 200
            //   0808                 | or                  byte ptr [eax], cl
            //   008a3800cc1c         | add                 byte ptr [edx + 0x1ccc0038], cl
            //   5e                   | pop                 esi
            //   006c70ff             | add                 byte ptr [eax + esi*2 - 1], ch
            //   0808                 | or                  byte ptr [eax], cl

        $sequence_7 = { 007168 ff0468 ff0a 250004003c }
            // n = 4, score = 200
            //   007168               | add                 byte ptr [ecx + 0x68], dh
            //   ff0468               | inc                 dword ptr [eax + ebp*2]
            //   ff0a                 | dec                 dword ptr [edx]
            //   250004003c           | and                 eax, 0x3c000400

        $sequence_8 = { ff15???????? 68fffe0000 ffd3 8bd0 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   68fffe0000           | push                0xfeff
            //   ffd3                 | call                ebx
            //   8bd0                 | mov                 edx, eax

        $sequence_9 = { ff15???????? 68???????? ffd7 8b1d???????? }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   8b1d????????         |                     

        $sequence_10 = { ff15???????? 6a00 6818000368 8b4508 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6818000368           | push                0x68030018
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_11 = { ff15???????? 68???????? ff15???????? 50 8d858cfeffff }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8d858cfeffff         | lea                 eax, [ebp - 0x174]

        $sequence_12 = { ff15???????? 69c0e8030000 0f80b50a0000 50 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   69c0e8030000         | imul                eax, eax, 0x3e8
            //   0f80b50a0000         | jo                  0xabb
            //   50                   | push                eax

        $sequence_13 = { ff15???????? 6a00 6822000360 8b03 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6822000360           | push                0x60030022
            //   8b03                 | mov                 eax, dword ptr [ebx]

        $sequence_14 = { ff15???????? 6a00 68???????? 6a00 68???????? 8b55e0 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   68????????           |                     
            //   6a00                 | push                0
            //   68????????           |                     
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]

        $sequence_15 = { ff15???????? 6a00 6806000368 8b4dd4 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6806000368           | push                0x68030006
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]

    condition:
        7 of them and filesize < 8560640
}