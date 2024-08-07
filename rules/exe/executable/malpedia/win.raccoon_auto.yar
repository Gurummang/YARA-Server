rule win_raccoon_auto {

    meta:
        atk_type = "win.raccoon."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.raccoon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.raccoon"
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
        $sequence_0 = { 8bf0 8975f0 85f6 7422 8d45ec c706???????? }
            // n = 6, score = 2400
            //   8bf0                 | mov                 esi, eax
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   85f6                 | test                esi, esi
            //   7422                 | je                  0x24
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   c706????????         |                     

        $sequence_1 = { e8???????? 68???????? eb31 51 }
            // n = 4, score = 2400
            //   e8????????           |                     
            //   68????????           |                     
            //   eb31                 | jmp                 0x33
            //   51                   | push                ecx

        $sequence_2 = { 8b45e8 3bc6 7c31 7f04 3bde 762b }
            // n = 6, score = 2400
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   3bc6                 | cmp                 eax, esi
            //   7c31                 | jl                  0x33
            //   7f04                 | jg                  6
            //   3bde                 | cmp                 ebx, esi
            //   762b                 | jbe                 0x2d

        $sequence_3 = { 53 50 8d45e0 895dd0 }
            // n = 4, score = 2400
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx

        $sequence_4 = { ff15???????? 8945f4 40 03c7 50 8945f0 }
            // n = 6, score = 2400
            //   ff15????????         |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   40                   | inc                 eax
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_5 = { ff15???????? 8bf0 83feff 7437 837b1410 7202 8b1b }
            // n = 7, score = 2400
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   7437                 | je                  0x39
            //   837b1410             | cmp                 dword ptr [ebx + 0x14], 0x10
            //   7202                 | jb                  4
            //   8b1b                 | mov                 ebx, dword ptr [ebx]

        $sequence_6 = { 8d45ec c706???????? 50 53 ff75e4 895dec ff15???????? }
            // n = 7, score = 2400
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   c706????????         |                     
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   ff15????????         |                     

        $sequence_7 = { 57 33db 8bf9 53 6aff 53 }
            // n = 6, score = 2400
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   8bf9                 | mov                 edi, ecx
            //   53                   | push                ebx
            //   6aff                 | push                -1
            //   53                   | push                ebx

        $sequence_8 = { 6a01 52 52 52 52 }
            // n = 5, score = 2400
            //   6a01                 | push                1
            //   52                   | push                edx
            //   52                   | push                edx
            //   52                   | push                edx
            //   52                   | push                edx

        $sequence_9 = { 0f85dd000000 57 57 57 57 8d45fc }
            // n = 6, score = 2400
            //   0f85dd000000         | jne                 0xe3
            //   57                   | push                edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   8d45fc               | lea                 eax, [ebp - 4]

    condition:
        7 of them and filesize < 1212416
}