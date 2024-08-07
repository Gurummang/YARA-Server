rule win_ahtapot_auto {

    meta:
        atk_type = "win.ahtapot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ahtapot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ahtapot"
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
        $sequence_0 = { 80e17f 3008 8b06 8bc8 c1f905 8b0c8dc0f24200 83e01f }
            // n = 7, score = 100
            //   80e17f               | and                 cl, 0x7f
            //   3008                 | xor                 byte ptr [eax], cl
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   8b0c8dc0f24200       | mov                 ecx, dword ptr [ecx*4 + 0x42f2c0]
            //   83e01f               | and                 eax, 0x1f

        $sequence_1 = { c686c312000001 e9???????? 6a00 6a00 56 68???????? 6a00 }
            // n = 7, score = 100
            //   c686c312000001       | mov                 byte ptr [esi + 0x12c3], 1
            //   e9????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   56                   | push                esi
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_2 = { 740b 8d85f0fdffff e8???????? 56 8d95f0fdffff 68???????? 52 }
            // n = 7, score = 100
            //   740b                 | je                  0xd
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d95f0fdffff         | lea                 edx, [ebp - 0x210]
            //   68????????           |                     
            //   52                   | push                edx

        $sequence_3 = { 8d95f0fdffff 52 ff15???????? 83f8ff 0f8585000000 8d837c060000 50 }
            // n = 7, score = 100
            //   8d95f0fdffff         | lea                 edx, [ebp - 0x210]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f8585000000         | jne                 0x8b
            //   8d837c060000         | lea                 eax, [ebx + 0x67c]
            //   50                   | push                eax

        $sequence_4 = { 8d8e6c020000 51 8d95acf1ffff 68???????? }
            // n = 4, score = 100
            //   8d8e6c020000         | lea                 ecx, [esi + 0x26c]
            //   51                   | push                ecx
            //   8d95acf1ffff         | lea                 edx, [ebp - 0xe54]
            //   68????????           |                     

        $sequence_5 = { 8d3c85c0f24200 8bf3 83e61f c1e606 8b07 0fbe440604 83e001 }
            // n = 7, score = 100
            //   8d3c85c0f24200       | lea                 edi, [eax*4 + 0x42f2c0]
            //   8bf3                 | mov                 esi, ebx
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   0fbe440604           | movsx               eax, byte ptr [esi + eax + 4]
            //   83e001               | and                 eax, 1

        $sequence_6 = { 8b958cf3ffff 8b8578f3ffff 8d8da8f3ffff 51 52 68???????? }
            // n = 6, score = 100
            //   8b958cf3ffff         | mov                 edx, dword ptr [ebp - 0xc74]
            //   8b8578f3ffff         | mov                 eax, dword ptr [ebp - 0xc88]
            //   8d8da8f3ffff         | lea                 ecx, [ebp - 0xc58]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   68????????           |                     

        $sequence_7 = { 8b5df0 8bf0 8b45ec 8d140b 52 50 56 }
            // n = 7, score = 100
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   8bf0                 | mov                 esi, eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8d140b               | lea                 edx, [ebx + ecx]
            //   52                   | push                edx
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_8 = { 83c404 8b1d???????? 8d95bcf9ffff 52 ffd3 8b859cf1ffff }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   8b1d????????         |                     
            //   8d95bcf9ffff         | lea                 edx, [ebp - 0x644]
            //   52                   | push                edx
            //   ffd3                 | call                ebx
            //   8b859cf1ffff         | mov                 eax, dword ptr [ebp - 0xe64]

        $sequence_9 = { e8???????? 68???????? 8d55ec 52 8975f8 897dfc c745ec20a04200 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   52                   | push                edx
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   c745ec20a04200       | mov                 dword ptr [ebp - 0x14], 0x42a020

    condition:
        7 of them and filesize < 430080
}