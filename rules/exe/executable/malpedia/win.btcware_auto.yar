rule win_btcware_auto {

    meta:
        atk_type = "win.btcware."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.btcware."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.btcware"
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
        $sequence_0 = { 53 ff15???????? 8b4524 83f810 7242 8b4d10 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8b4524               | mov                 eax, dword ptr [ebp + 0x24]
            //   83f810               | cmp                 eax, 0x10
            //   7242                 | jb                  0x44
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]

        $sequence_1 = { c7404818c14100 8b4508 6689486c 8b4508 66898872010000 8d4dff 8b4508 }
            // n = 7, score = 100
            //   c7404818c14100       | mov                 dword ptr [eax + 0x48], 0x41c118
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   6689486c             | mov                 word ptr [eax + 0x6c], cx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   66898872010000       | mov                 word ptr [eax + 0x172], cx
            //   8d4dff               | lea                 ecx, [ebp - 1]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_2 = { 33c5 8945fc 8b450c 56 8b7508 680a010000 }
            // n = 6, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   680a010000           | push                0x10a

        $sequence_3 = { 33c0 85ff 7e18 0fb78c4490020000 663bce 7406 66894c5440 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   85ff                 | test                edi, edi
            //   7e18                 | jle                 0x1a
            //   0fb78c4490020000     | movzx               ecx, word ptr [esp + eax*2 + 0x290]
            //   663bce               | cmp                 cx, si
            //   7406                 | je                  8
            //   66894c5440           | mov                 word ptr [esp + edx*2 + 0x40], cx

        $sequence_4 = { 50 8d44241c 50 ff74241c ff15???????? 85c0 7446 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   50                   | push                eax
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7446                 | je                  0x48

        $sequence_5 = { 33db 895610 c746140f000000 8975d4 8955e4 }
            // n = 5, score = 100
            //   33db                 | xor                 ebx, ebx
            //   895610               | mov                 dword ptr [esi + 0x10], edx
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   8975d4               | mov                 dword ptr [ebp - 0x2c], esi
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx

        $sequence_6 = { 8d85f8efffff 50 ffd7 85c0 0f84ac000000 8d85f4efffff }
            // n = 6, score = 100
            //   8d85f8efffff         | lea                 eax, [ebp - 0x1008]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   0f84ac000000         | je                  0xb2
            //   8d85f4efffff         | lea                 eax, [ebp - 0x100c]

        $sequence_7 = { 85c0 0f84ac000000 8d85f4efffff 50 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   0f84ac000000         | je                  0xb2
            //   8d85f4efffff         | lea                 eax, [ebp - 0x100c]
            //   50                   | push                eax

        $sequence_8 = { 6800010000 8d85fcfcffff 50 68???????? ff15???????? 8b35???????? }
            // n = 6, score = 100
            //   6800010000           | push                0x100
            //   8d85fcfcffff         | lea                 eax, [ebp - 0x304]
            //   50                   | push                eax
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b35????????         |                     

        $sequence_9 = { 8d85e0efffff 50 6a00 6800800000 ffb5f0efffff 8d85fcefffff 50 }
            // n = 7, score = 100
            //   8d85e0efffff         | lea                 eax, [ebp - 0x1020]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6800800000           | push                0x8000
            //   ffb5f0efffff         | push                dword ptr [ebp - 0x1010]
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 458752
}