rule win_catchamas_auto {

    meta:
        atk_type = "win.catchamas."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.catchamas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.catchamas"
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
        $sequence_0 = { ffd6 6808080000 8d54246c 52 }
            // n = 4, score = 200
            //   ffd6                 | call                esi
            //   6808080000           | push                0x808
            //   8d54246c             | lea                 edx, [esp + 0x6c]
            //   52                   | push                edx

        $sequence_1 = { 5f 5e 8b8c247c200000 33cc e8???????? }
            // n = 5, score = 200
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b8c247c200000       | mov                 ecx, dword ptr [esp + 0x207c]
            //   33cc                 | xor                 ecx, esp
            //   e8????????           |                     

        $sequence_2 = { 6a00 ff15???????? e8???????? 8bcb 8b5c244c 51 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   e8????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   8b5c244c             | mov                 ebx, dword ptr [esp + 0x4c]
            //   51                   | push                ecx

        $sequence_3 = { 6683f814 0f84c4080000 833d????????00 0f85af000000 }
            // n = 4, score = 200
            //   6683f814             | cmp                 ax, 0x14
            //   0f84c4080000         | je                  0x8ca
            //   833d????????00       |                     
            //   0f85af000000         | jne                 0xb5

        $sequence_4 = { 50 bf01000000 ff15???????? 56 ff15???????? 85ff 0f851a010000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   bf01000000           | mov                 edi, 1
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85ff                 | test                edi, edi
            //   0f851a010000         | jne                 0x120

        $sequence_5 = { 50 8d8c2494100000 68???????? 51 ff15???????? 83c42c 33c0 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d8c2494100000       | lea                 ecx, [esp + 0x1094]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c42c               | add                 esp, 0x2c
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 84c0 8b45e0 7409 e8???????? 8bfc eb32 }
            // n = 6, score = 200
            //   84c0                 | test                al, al
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   7409                 | je                  0xb
            //   e8????????           |                     
            //   8bfc                 | mov                 edi, esp
            //   eb32                 | jmp                 0x34

        $sequence_7 = { ffd7 6a0a 56 8be8 ffd7 8bf8 }
            // n = 6, score = 200
            //   ffd7                 | call                edi
            //   6a0a                 | push                0xa
            //   56                   | push                esi
            //   8be8                 | mov                 ebp, eax
            //   ffd7                 | call                edi
            //   8bf8                 | mov                 edi, eax

        $sequence_8 = { 83e802 0f84bf090000 83e80d 0f845a090000 }
            // n = 4, score = 200
            //   83e802               | sub                 eax, 2
            //   0f84bf090000         | je                  0x9c5
            //   83e80d               | sub                 eax, 0xd
            //   0f845a090000         | je                  0x960

        $sequence_9 = { 51 57 8bf0 50 ebbd e8???????? }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   57                   | push                edi
            //   8bf0                 | mov                 esi, eax
            //   50                   | push                eax
            //   ebbd                 | jmp                 0xffffffbf
            //   e8????????           |                     

    condition:
        7 of them and filesize < 368640
}