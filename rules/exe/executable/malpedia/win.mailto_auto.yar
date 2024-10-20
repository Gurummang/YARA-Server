rule win_mailto_auto {

    meta:
        atk_type = "win.mailto."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mailto."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mailto"
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
        $sequence_0 = { 47 3bfb 7297 8b44241c 8930 8b442420 85c0 }
            // n = 7, score = 400
            //   47                   | inc                 edi
            //   3bfb                 | cmp                 edi, ebx
            //   7297                 | jb                  0xffffff99
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   8930                 | mov                 dword ptr [eax], esi
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   85c0                 | test                eax, eax

        $sequence_1 = { 83c404 85f6 7429 85ed 7419 8b742414 }
            // n = 6, score = 400
            //   83c404               | add                 esp, 4
            //   85f6                 | test                esi, esi
            //   7429                 | je                  0x2b
            //   85ed                 | test                ebp, ebp
            //   7419                 | je                  0x1b
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]

        $sequence_2 = { 8b442418 8938 8b44241c 85c0 7402 8930 }
            // n = 6, score = 400
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8938                 | mov                 dword ptr [eax], edi
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4
            //   8930                 | mov                 dword ptr [eax], esi

        $sequence_3 = { 55 56 57 8b7c2424 c744241400000000 85ff 7457 }
            // n = 7, score = 400
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7c2424             | mov                 edi, dword ptr [esp + 0x24]
            //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
            //   85ff                 | test                edi, edi
            //   7457                 | je                  0x59

        $sequence_4 = { 85f6 0f8477010000 e8???????? 3b7014 0f8469010000 8b0d???????? 85c9 }
            // n = 7, score = 400
            //   85f6                 | test                esi, esi
            //   0f8477010000         | je                  0x17d
            //   e8????????           |                     
            //   3b7014               | cmp                 esi, dword ptr [eax + 0x14]
            //   0f8469010000         | je                  0x16f
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx

        $sequence_5 = { 8b08 ff5130 85c0 7822 ff74242c e8???????? }
            // n = 6, score = 400
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5130               | call                dword ptr [ecx + 0x30]
            //   85c0                 | test                eax, eax
            //   7822                 | js                  0x24
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   e8????????           |                     

        $sequence_6 = { 897c242c 8bc8 89442420 c1f81a c1f91f 23c8 8bc1 }
            // n = 7, score = 400
            //   897c242c             | mov                 dword ptr [esp + 0x2c], edi
            //   8bc8                 | mov                 ecx, eax
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   c1f81a               | sar                 eax, 0x1a
            //   c1f91f               | sar                 ecx, 0x1f
            //   23c8                 | and                 ecx, eax
            //   8bc1                 | mov                 eax, ecx

        $sequence_7 = { 40 eb64 83ff01 7522 0fb6d1 bf02000000 83e203 }
            // n = 7, score = 400
            //   40                   | inc                 eax
            //   eb64                 | jmp                 0x66
            //   83ff01               | cmp                 edi, 1
            //   7522                 | jne                 0x24
            //   0fb6d1               | movzx               edx, cl
            //   bf02000000           | mov                 edi, 2
            //   83e203               | and                 edx, 3

        $sequence_8 = { 0fb6466b 884118 0fb6466f 88411c 0fb64652 884101 0fb64656 }
            // n = 7, score = 400
            //   0fb6466b             | movzx               eax, byte ptr [esi + 0x6b]
            //   884118               | mov                 byte ptr [ecx + 0x18], al
            //   0fb6466f             | movzx               eax, byte ptr [esi + 0x6f]
            //   88411c               | mov                 byte ptr [ecx + 0x1c], al
            //   0fb64652             | movzx               eax, byte ptr [esi + 0x52]
            //   884101               | mov                 byte ptr [ecx + 1], al
            //   0fb64656             | movzx               eax, byte ptr [esi + 0x56]

        $sequence_9 = { 0f84ef000000 6a20 e8???????? 83c404 89442410 85c0 }
            // n = 6, score = 400
            //   0f84ef000000         | je                  0xf5
            //   6a20                 | push                0x20
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 180224
}