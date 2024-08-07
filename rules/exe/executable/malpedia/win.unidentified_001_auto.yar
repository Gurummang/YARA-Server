rule win_unidentified_001_auto {

    meta:
        atk_type = "win.unidentified_001."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_001."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_001"
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
        $sequence_0 = { 6830750000 ffd6 8b4df8 85c9 7483 8d45fc }
            // n = 6, score = 100
            //   6830750000           | push                0x7530
            //   ffd6                 | call                esi
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   85c9                 | test                ecx, ecx
            //   7483                 | je                  0xffffff85
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_1 = { fec1 88143e 3a4801 72e6 5f 5e 5d }
            // n = 7, score = 100
            //   fec1                 | inc                 cl
            //   88143e               | mov                 byte ptr [esi + edi], dl
            //   3a4801               | cmp                 cl, byte ptr [eax + 1]
            //   72e6                 | jb                  0xffffffe8
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_2 = { 2bc6 0f8421fdffff 2df2020000 0f8478fbffff 2d13030000 }
            // n = 5, score = 100
            //   2bc6                 | sub                 eax, esi
            //   0f8421fdffff         | je                  0xfffffd27
            //   2df2020000           | sub                 eax, 0x2f2
            //   0f8478fbffff         | je                  0xfffffb7e
            //   2d13030000           | sub                 eax, 0x313

        $sequence_3 = { b952555300 3bc1 7767 74d3 }
            // n = 4, score = 100
            //   b952555300           | mov                 ecx, 0x535552
            //   3bc1                 | cmp                 eax, ecx
            //   7767                 | ja                  0x69
            //   74d3                 | je                  0xffffffd5

        $sequence_4 = { 8bf1 8b06 57 56 ff5048 8bf8 85ff }
            // n = 7, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff5048               | call                dword ptr [eax + 0x48]
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi

        $sequence_5 = { ff15???????? 50 ff15???????? 8bf0 8975f8 3bf3 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   3bf3                 | cmp                 esi, ebx

        $sequence_6 = { 893d???????? e9???????? c705????????10000000 e9???????? 2d46494e00 7461 48 }
            // n = 7, score = 100
            //   893d????????         |                     
            //   e9????????           |                     
            //   c705????????10000000     |     
            //   e9????????           |                     
            //   2d46494e00           | sub                 eax, 0x4e4946
            //   7461                 | je                  0x63
            //   48                   | dec                 eax

        $sequence_7 = { 6a04 68???????? 6a07 6800080000 }
            // n = 4, score = 100
            //   6a04                 | push                4
            //   68????????           |                     
            //   6a07                 | push                7
            //   6800080000           | push                0x800

        $sequence_8 = { 8935???????? 8d45cc 50 57 }
            // n = 4, score = 100
            //   8935????????         |                     
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_9 = { 50 ff5108 8b45e4 3bc3 5b 7406 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ff5108               | call                dword ptr [ecx + 8]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   3bc3                 | cmp                 eax, ebx
            //   5b                   | pop                 ebx
            //   7406                 | je                  8

    condition:
        7 of them and filesize < 65536
}