rule win_mydoom_auto {

    meta:
        atk_type = "win.mydoom."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mydoom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mydoom"
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
        $sequence_0 = { 0f94c2 83f842 0f94c0 09d0 ba00000000 a801 0f8531010000 }
            // n = 7, score = 100
            //   0f94c2               | sete                dl
            //   83f842               | cmp                 eax, 0x42
            //   0f94c0               | sete                al
            //   09d0                 | or                  eax, edx
            //   ba00000000           | mov                 edx, 0
            //   a801                 | test                al, 1
            //   0f8531010000         | jne                 0x137

        $sequence_1 = { 49 c744241000000000 8d85c4fdffff 8944240c 894c2408 }
            // n = 5, score = 100
            //   49                   | dec                 ecx
            //   c744241000000000     | mov                 dword ptr [esp + 0x10], 0
            //   8d85c4fdffff         | lea                 eax, [ebp - 0x23c]
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   894c2408             | mov                 dword ptr [esp + 8], ecx

        $sequence_2 = { 891c24 e8???????? 85c0 743c 8b85d8feffff 89442404 891c24 }
            // n = 7, score = 100
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   743c                 | je                  0x3e
            //   8b85d8feffff         | mov                 eax, dword ptr [ebp - 0x128]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   891c24               | mov                 dword ptr [esp], ebx

        $sequence_3 = { 891c24 e8???????? 83ec04 c744240402000000 }
            // n = 4, score = 100
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   83ec04               | sub                 esp, 4
            //   c744240402000000     | mov                 dword ptr [esp + 4], 2

        $sequence_4 = { 85c0 89c3 7413 89f6 8dbc2700000000 ff149df8354200 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   89c3                 | mov                 ebx, eax
            //   7413                 | je                  0x15
            //   89f6                 | mov                 esi, esi
            //   8dbc2700000000       | lea                 edi, [edi]
            //   ff149df8354200       | call                dword ptr [ebx*4 + 0x4235f8]

        $sequence_5 = { 8d9dc8f9ffff 891c24 e8???????? 8d8568f9ffff 89442424 89742420 }
            // n = 6, score = 100
            //   8d9dc8f9ffff         | lea                 ebx, [ebp - 0x638]
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   8d8568f9ffff         | lea                 eax, [ebp - 0x698]
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   89742420             | mov                 dword ptr [esp + 0x20], esi

        $sequence_6 = { 83ec58 895df4 8975f8 897dfc 8b7510 0fb74514 668945e6 }
            // n = 7, score = 100
            //   83ec58               | sub                 esp, 0x58
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   0fb74514             | movzx               eax, word ptr [ebp + 0x14]
            //   668945e6             | mov                 word ptr [ebp - 0x1a], ax

        $sequence_7 = { 89e5 56 53 83ec10 8b750c 83fe01 }
            // n = 6, score = 100
            //   89e5                 | mov                 ebp, esp
            //   56                   | push                esi
            //   53                   | push                ebx
            //   83ec10               | sub                 esp, 0x10
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   83fe01               | cmp                 esi, 1

        $sequence_8 = { 890424 e8???????? e8???????? 8db406fc2f0000 0fb745e6 }
            // n = 5, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   8db406fc2f0000       | lea                 esi, [esi + eax + 0x2ffc]
            //   0fb745e6             | movzx               eax, word ptr [ebp - 0x1a]

        $sequence_9 = { 85d0 7547 85f6 750c 8b0d???????? 85c9 7546 }
            // n = 7, score = 100
            //   85d0                 | test                eax, edx
            //   7547                 | jne                 0x49
            //   85f6                 | test                esi, esi
            //   750c                 | jne                 0xe
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx
            //   7546                 | jne                 0x48

    condition:
        7 of them and filesize < 114688
}