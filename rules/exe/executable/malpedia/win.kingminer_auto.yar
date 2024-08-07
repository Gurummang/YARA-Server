rule win_kingminer_auto {

    meta:
        atk_type = "win.kingminer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.kingminer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kingminer"
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
        $sequence_0 = { a1???????? 885c30fe a1???????? 0fb64c30f9 884c30fc }
            // n = 5, score = 100
            //   a1????????           |                     
            //   885c30fe             | mov                 byte ptr [eax + esi - 2], bl
            //   a1????????           |                     
            //   0fb64c30f9           | movzx               ecx, byte ptr [eax + esi - 7]
            //   884c30fc             | mov                 byte ptr [eax + esi - 4], cl

        $sequence_1 = { ff15???????? 6a01 ff15???????? 6a00 ff15???????? 8b4508 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_2 = { 83c40c 807c30ff62 8d4c30ff 0f8599010000 }
            // n = 4, score = 100
            //   83c40c               | add                 esp, 0xc
            //   807c30ff62           | cmp                 byte ptr [eax + esi - 1], 0x62
            //   8d4c30ff             | lea                 ecx, [eax + esi - 1]
            //   0f8599010000         | jne                 0x19f

        $sequence_3 = { ff15???????? 6a00 ff15???????? 8b80c0000000 85c0 7422 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8b80c0000000         | mov                 eax, dword ptr [eax + 0xc0]
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24

        $sequence_4 = { 6a00 ff15???????? 6a00 ff15???????? 6a01 ff15???????? 6a00 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_5 = { 3bf0 741e 68c1000000 ff15???????? 5b }
            // n = 5, score = 100
            //   3bf0                 | cmp                 esi, eax
            //   741e                 | je                  0x20
            //   68c1000000           | push                0xc1
            //   ff15????????         |                     
            //   5b                   | pop                 ebx

        $sequence_6 = { ff15???????? a1???????? 50 ffd7 ff15???????? 6a01 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   a1????????           |                     
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   ff15????????         |                     

        $sequence_7 = { 6a04 6800100000 51 52 ffd0 83c414 85c0 }
            // n = 7, score = 100
            //   6a04                 | push                4
            //   6800100000           | push                0x1000
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ffd0                 | call                eax
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax

        $sequence_8 = { 8d4dec 51 8d580c 56 8bc7 c745ec89480489 }
            // n = 6, score = 100
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   51                   | push                ecx
            //   8d580c               | lea                 ebx, [eax + 0xc]
            //   56                   | push                esi
            //   8bc7                 | mov                 eax, edi
            //   c745ec89480489       | mov                 dword ptr [ebp - 0x14], 0x89044889

        $sequence_9 = { 8b95d0feffff 2b4234 7419 83b9a000000000 7466 50 }
            // n = 6, score = 100
            //   8b95d0feffff         | mov                 edx, dword ptr [ebp - 0x130]
            //   2b4234               | sub                 eax, dword ptr [edx + 0x34]
            //   7419                 | je                  0x1b
            //   83b9a000000000       | cmp                 dword ptr [ecx + 0xa0], 0
            //   7466                 | je                  0x68
            //   50                   | push                eax

    condition:
        7 of them and filesize < 165888
}