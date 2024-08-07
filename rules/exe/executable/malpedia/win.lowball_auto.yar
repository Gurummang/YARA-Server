rule win_lowball_auto {

    meta:
        atk_type = "win.lowball."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lowball."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowball"
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
        $sequence_0 = { 0f8436010000 8b942430060000 33c9 85d2 740c 8bfa }
            // n = 6, score = 100
            //   0f8436010000         | je                  0x13c
            //   8b942430060000       | mov                 edx, dword ptr [esp + 0x630]
            //   33c9                 | xor                 ecx, ecx
            //   85d2                 | test                edx, edx
            //   740c                 | je                  0xe
            //   8bfa                 | mov                 edi, edx

        $sequence_1 = { ff54242c 5f 5e 5d 33c0 }
            // n = 5, score = 100
            //   ff54242c             | call                dword ptr [esp + 0x2c]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 8d4f01 51 e8???????? 56 8bd8 ff15???????? }
            // n = 6, score = 100
            //   8d4f01               | lea                 ecx, [edi + 1]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   56                   | push                esi
            //   8bd8                 | mov                 ebx, eax
            //   ff15????????         |                     

        $sequence_3 = { 68???????? f3a4 6a00 ff54242c 6810270000 ff15???????? bf???????? }
            // n = 7, score = 100
            //   68????????           |                     
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   6a00                 | push                0
            //   ff54242c             | call                dword ptr [esp + 0x2c]
            //   6810270000           | push                0x2710
            //   ff15????????         |                     
            //   bf????????           |                     

        $sequence_4 = { 85ff 897c240c 0f848c000000 8b942420020000 55 }
            // n = 5, score = 100
            //   85ff                 | test                edi, edi
            //   897c240c             | mov                 dword ptr [esp + 0xc], edi
            //   0f848c000000         | je                  0x92
            //   8b942420020000       | mov                 edx, dword ptr [esp + 0x220]
            //   55                   | push                ebp

        $sequence_5 = { c1e902 f3a5 8bcb 8d84244c0d0000 83e103 50 }
            // n = 6, score = 100
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bcb                 | mov                 ecx, ebx
            //   8d84244c0d0000       | lea                 eax, [esp + 0xd4c]
            //   83e103               | and                 ecx, 3
            //   50                   | push                eax

        $sequence_6 = { 83c410 85c0 752d 68b80b0000 ffd3 8d8c24400a0000 8d94241c010000 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   752d                 | jne                 0x2f
            //   68b80b0000           | push                0xbb8
            //   ffd3                 | call                ebx
            //   8d8c24400a0000       | lea                 ecx, [esp + 0xa40]
            //   8d94241c010000       | lea                 edx, [esp + 0x11c]

        $sequence_7 = { 8bc1 8bf7 8bfa 8d942434070000 c1e902 f3a5 8bc8 }
            // n = 7, score = 100
            //   8bc1                 | mov                 eax, ecx
            //   8bf7                 | mov                 esi, edi
            //   8bfa                 | mov                 edi, edx
            //   8d942434070000       | lea                 edx, [esp + 0x734]
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax

        $sequence_8 = { ff15???????? 83c404 89442410 b905000000 be???????? }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   b905000000           | mov                 ecx, 5
            //   be????????           |                     

        $sequence_9 = { 6a00 6a00 68bb010000 51 56 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68bb010000           | push                0x1bb
            //   51                   | push                ecx
            //   56                   | push                esi

    condition:
        7 of them and filesize < 40960
}