rule win_avzhan_auto {

    meta:
        atk_type = "win.avzhan."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.avzhan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avzhan"
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
        $sequence_0 = { f3aa 8b3d???????? 833d????????01 7418 }
            // n = 4, score = 200
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   8b3d????????         |                     
            //   833d????????01       |                     
            //   7418                 | je                  0x1a

        $sequence_1 = { 75e8 6a14 ff15???????? 833d????????01 75d2 }
            // n = 5, score = 200
            //   75e8                 | jne                 0xffffffea
            //   6a14                 | push                0x14
            //   ff15????????         |                     
            //   833d????????01       |                     
            //   75d2                 | jne                 0xffffffd4

        $sequence_2 = { 8bf0 8dbc2404020000 83c9ff 33c0 83c408 f2ae }
            // n = 6, score = 200
            //   8bf0                 | mov                 esi, eax
            //   8dbc2404020000       | lea                 edi, [esp + 0x204]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   83c408               | add                 esp, 8
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_3 = { 68???????? 51 ff15???????? 8b2d???????? 8b1d???????? b910000000 }
            // n = 6, score = 200
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b2d????????         |                     
            //   8b1d????????         |                     
            //   b910000000           | mov                 ecx, 0x10

        $sequence_4 = { 8d442464 52 50 e8???????? 83c404 50 e8???????? }
            // n = 7, score = 200
            //   8d442464             | lea                 eax, [esp + 0x64]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { 6a00 6a00 6a00 6a00 6a00 8d8c2418020000 6a00 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d8c2418020000       | lea                 ecx, [esp + 0x218]
            //   6a00                 | push                0

        $sequence_6 = { 83c408 f2ae f7d1 6a00 51 8d8c2404020000 51 }
            // n = 7, score = 200
            //   83c408               | add                 esp, 8
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8d8c2404020000       | lea                 ecx, [esp + 0x204]
            //   51                   | push                ecx

        $sequence_7 = { 8bc3 83c408 c1e010 668bc3 8b1d???????? c1e902 }
            // n = 6, score = 200
            //   8bc3                 | mov                 eax, ebx
            //   83c408               | add                 esp, 8
            //   c1e010               | shl                 eax, 0x10
            //   668bc3               | mov                 ax, bx
            //   8b1d????????         |                     
            //   c1e902               | shr                 ecx, 2

        $sequence_8 = { 6a00 51 6a00 ffd5 85c0 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   ffd5                 | call                ebp
            //   85c0                 | test                eax, eax

        $sequence_9 = { 51 8d842484010000 52 50 }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   8d842484010000       | lea                 eax, [esp + 0x184]
            //   52                   | push                edx
            //   50                   | push                eax

    condition:
        7 of them and filesize < 122880
}