rule win_yayih_auto {

    meta:
        atk_type = "win.yayih."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.yayih."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yayih"
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
        $sequence_0 = { 5f ff7508 ff55f4 53 ff15???????? 8bc7 }
            // n = 6, score = 100
            //   5f                   | pop                 edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff55f4               | call                dword ptr [ebp - 0xc]
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8bc7                 | mov                 eax, edi

        $sequence_1 = { 68???????? e8???????? 8b35???????? 83c40c 50 57 }
            // n = 6, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   8b35????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_2 = { 50 56 e8???????? 59 85c0 59 753c }
            // n = 7, score = 100
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   753c                 | jne                 0x3e

        $sequence_3 = { 85c0 59 7507 57 e8???????? 59 e8???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   7507                 | jne                 9
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   e8????????           |                     

        $sequence_4 = { ff15???????? 56 6880000000 6a03 56 6a01 8d85b8b8ffff }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   56                   | push                esi
            //   6880000000           | push                0x80
            //   6a03                 | push                3
            //   56                   | push                esi
            //   6a01                 | push                1
            //   8d85b8b8ffff         | lea                 eax, [ebp - 0x4748]

        $sequence_5 = { 66ab aa 59 33c0 8dbde9faffff 889de8faffff f3ab }
            // n = 7, score = 100
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   8dbde9faffff         | lea                 edi, [ebp - 0x517]
            //   889de8faffff         | mov                 byte ptr [ebp - 0x518], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_6 = { 3bfe 750a 56 56 56 6a08 }
            // n = 6, score = 100
            //   3bfe                 | cmp                 edi, esi
            //   750a                 | jne                 0xc
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   6a08                 | push                8

        $sequence_7 = { e8???????? 6801200000 8d85b8b8ffff 56 50 e8???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   6801200000           | push                0x2001
            //   8d85b8b8ffff         | lea                 eax, [ebp - 0x4748]
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { 50 8d854cf6ffff 50 e8???????? 83c430 8d459c 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d854cf6ffff         | lea                 eax, [ebp - 0x9b4]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   50                   | push                eax

        $sequence_9 = { 0fafca 0fb65002 03ca 890d???????? 0fb64803 69c960ea0000 }
            // n = 6, score = 100
            //   0fafca               | imul                ecx, edx
            //   0fb65002             | movzx               edx, byte ptr [eax + 2]
            //   03ca                 | add                 ecx, edx
            //   890d????????         |                     
            //   0fb64803             | movzx               ecx, byte ptr [eax + 3]
            //   69c960ea0000         | imul                ecx, ecx, 0xea60

    condition:
        7 of them and filesize < 57344
}