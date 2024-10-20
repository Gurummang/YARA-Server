rule win_racket_auto {

    meta:
        atk_type = "win.racket."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.racket."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.racket"
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
        $sequence_0 = { ffd3 8b8eec000000 8bf8 8b1d???????? 8d45ec 57 50 }
            // n = 7, score = 100
            //   ffd3                 | call                ebx
            //   8b8eec000000         | mov                 ecx, dword ptr [esi + 0xec]
            //   8bf8                 | mov                 edi, eax
            //   8b1d????????         |                     
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   57                   | push                edi
            //   50                   | push                eax

        $sequence_1 = { 807d0800 743b e8???????? 6a00 ff7604 6845090000 ff35???????? }
            // n = 7, score = 100
            //   807d0800             | cmp                 byte ptr [ebp + 8], 0
            //   743b                 | je                  0x3d
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff7604               | push                dword ptr [esi + 4]
            //   6845090000           | push                0x945
            //   ff35????????         |                     

        $sequence_2 = { 57 0f1f840000000000 8bc1 c745fc02000000 2bc2 8dbb78fdffff 81c680fdffff }
            // n = 7, score = 100
            //   57                   | push                edi
            //   0f1f840000000000     | nop                 dword ptr [eax + eax]
            //   8bc1                 | mov                 eax, ecx
            //   c745fc02000000       | mov                 dword ptr [ebp - 4], 2
            //   2bc2                 | sub                 eax, edx
            //   8dbb78fdffff         | lea                 edi, [ebx - 0x288]
            //   81c680fdffff         | add                 esi, 0xfffffd80

        $sequence_3 = { 0f44c1 50 ff75f4 8b473c 68a2090000 ff34856cb30610 ff15???????? }
            // n = 7, score = 100
            //   0f44c1               | cmove               eax, ecx
            //   50                   | push                eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   8b473c               | mov                 eax, dword ptr [edi + 0x3c]
            //   68a2090000           | push                0x9a2
            //   ff34856cb30610       | push                dword ptr [eax*4 + 0x1006b36c]
            //   ff15????????         |                     

        $sequence_4 = { 40 50 68???????? 6aff 8d85fcfdffff 6800010000 50 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   68????????           |                     
            //   6aff                 | push                -1
            //   8d85fcfdffff         | lea                 eax, [ebp - 0x204]
            //   6800010000           | push                0x100
            //   50                   | push                eax

        $sequence_5 = { 0f8433020000 833d????????00 0f8426020000 833d????????00 0f8419020000 833d????????00 0f840c020000 }
            // n = 7, score = 100
            //   0f8433020000         | je                  0x239
            //   833d????????00       |                     
            //   0f8426020000         | je                  0x22c
            //   833d????????00       |                     
            //   0f8419020000         | je                  0x21f
            //   833d????????00       |                     
            //   0f840c020000         | je                  0x212

        $sequence_6 = { 83c430 3945cc 8b45b8 7501 40 8b4dc0 }
            // n = 6, score = 100
            //   83c430               | add                 esp, 0x30
            //   3945cc               | cmp                 dword ptr [ebp - 0x34], eax
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   7501                 | jne                 3
            //   40                   | inc                 eax
            //   8b4dc0               | mov                 ecx, dword ptr [ebp - 0x40]

        $sequence_7 = { 8b4e04 85c9 7537 8b4510 8b7838 85ff 7e75 }
            // n = 7, score = 100
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   85c9                 | test                ecx, ecx
            //   7537                 | jne                 0x39
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b7838               | mov                 edi, dword ptr [eax + 0x38]
            //   85ff                 | test                edi, edi
            //   7e75                 | jle                 0x77

        $sequence_8 = { ff740e08 68ac080000 ff35???????? ff15???????? 83c420 2bd8 7418 }
            // n = 7, score = 100
            //   ff740e08             | push                dword ptr [esi + ecx + 8]
            //   68ac080000           | push                0x8ac
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   83c420               | add                 esp, 0x20
            //   2bd8                 | sub                 ebx, eax
            //   7418                 | je                  0x1a

        $sequence_9 = { 6a00 68d6070000 897ddc ff34856cb30610 8975d0 ff15???????? 83c410 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   68d6070000           | push                0x7d6
            //   897ddc               | mov                 dword ptr [ebp - 0x24], edi
            //   ff34856cb30610       | push                dword ptr [eax*4 + 0x1006b36c]
            //   8975d0               | mov                 dword ptr [ebp - 0x30], esi
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10

    condition:
        7 of them and filesize < 985088
}