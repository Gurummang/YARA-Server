rule win_coronavirus_ransomware_auto {

    meta:
        atk_type = "win.coronavirus_ransomware."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.coronavirus_ransomware."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.coronavirus_ransomware"
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
        $sequence_0 = { 8d9b00000000 0fb708 66890c02 83c002 6685c9 75f1 8d8dec7effff }
            // n = 7, score = 100
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   0fb708               | movzx               ecx, word ptr [eax]
            //   66890c02             | mov                 word ptr [edx + eax], cx
            //   83c002               | add                 eax, 2
            //   6685c9               | test                cx, cx
            //   75f1                 | jne                 0xfffffff3
            //   8d8dec7effff         | lea                 ecx, [ebp - 0x8114]

        $sequence_1 = { 894dd8 837e0400 8b5608 c745dc00000000 8955e0 750a 8b45cc }
            // n = 7, score = 100
            //   894dd8               | mov                 dword ptr [ebp - 0x28], ecx
            //   837e0400             | cmp                 dword ptr [esi + 4], 0
            //   8b5608               | mov                 edx, dword ptr [esi + 8]
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   750a                 | jne                 0xc
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]

        $sequence_2 = { 50 ff15???????? 85c0 7420 b8???????? e8???????? 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7420                 | je                  0x22
            //   b8????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_3 = { 68fe1f0000 52 8d859e9fffff 50 e8???????? 33c9 }
            // n = 6, score = 100
            //   68fe1f0000           | push                0x1ffe
            //   52                   | push                edx
            //   8d859e9fffff         | lea                 eax, [ebp - 0x6062]
            //   50                   | push                eax
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx

        $sequence_4 = { 83c002 50 52 68???????? 8d8500c0ffff }
            // n = 5, score = 100
            //   83c002               | add                 eax, 2
            //   50                   | push                eax
            //   52                   | push                edx
            //   68????????           |                     
            //   8d8500c0ffff         | lea                 eax, [ebp - 0x4000]

        $sequence_5 = { 53 e8???????? 83c410 85ff 743b 8d4900 803c1fc3 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85ff                 | test                edi, edi
            //   743b                 | je                  0x3d
            //   8d4900               | lea                 ecx, [ecx]
            //   803c1fc3             | cmp                 byte ptr [edi + ebx], 0xc3

        $sequence_6 = { ff15???????? 8b15???????? a1???????? 83c418 52 6a01 50 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b15????????         |                     
            //   a1????????           |                     
            //   83c418               | add                 esp, 0x18
            //   52                   | push                edx
            //   6a01                 | push                1
            //   50                   | push                eax

        $sequence_7 = { 8b55d0 880417 8b45c8 50 ff15???????? 56 ff15???????? }
            // n = 7, score = 100
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   880417               | mov                 byte ptr [edi + edx], al
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_8 = { ffd6 a3???????? eb0a 53 }
            // n = 4, score = 100
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   eb0a                 | jmp                 0xc
            //   53                   | push                ebx

        $sequence_9 = { ff15???????? 85c0 7407 ffd0 a3???????? be???????? e8???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   ffd0                 | call                eax
            //   a3????????           |                     
            //   be????????           |                     
            //   e8????????           |                     

    condition:
        7 of them and filesize < 235520
}