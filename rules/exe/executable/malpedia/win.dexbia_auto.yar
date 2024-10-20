rule win_dexbia_auto {

    meta:
        atk_type = "win.dexbia."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.dexbia."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dexbia"
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
        $sequence_0 = { 8bfd b908000000 be???????? 83c520 83c320 }
            // n = 5, score = 200
            //   8bfd                 | mov                 edi, ebp
            //   b908000000           | mov                 ecx, 8
            //   be????????           |                     
            //   83c520               | add                 ebp, 0x20
            //   83c320               | add                 ebx, 0x20

        $sequence_1 = { a3???????? e8???????? 8db6ec894000 bf???????? }
            // n = 4, score = 200
            //   a3????????           |                     
            //   e8????????           |                     
            //   8db6ec894000         | lea                 esi, [esi + 0x4089ec]
            //   bf????????           |                     

        $sequence_2 = { ff15???????? 85c0 740c 8b442414 85c0 742a }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740c                 | je                  0xe
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   85c0                 | test                eax, eax
            //   742a                 | je                  0x2c

        $sequence_3 = { 5b 81c4e81b0000 c20400 57 ff15???????? b97f000000 33c0 }
            // n = 7, score = 200
            //   5b                   | pop                 ebx
            //   81c4e81b0000         | add                 esp, 0x1be8
            //   c20400               | ret                 4
            //   57                   | push                edi
            //   ff15????????         |                     
            //   b97f000000           | mov                 ecx, 0x7f
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { f3a5 8bcb 8d442410 83e103 50 f3a4 68???????? }
            // n = 7, score = 200
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bcb                 | mov                 ecx, ebx
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   83e103               | and                 ecx, 3
            //   50                   | push                eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   68????????           |                     

        $sequence_5 = { 5e 5d 33c0 5b 81c408100000 c3 68???????? }
            // n = 7, score = 200
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   81c408100000         | add                 esp, 0x1008
            //   c3                   | ret                 
            //   68????????           |                     

        $sequence_6 = { 50 ffd5 a1???????? 85c0 0f841dffffff e8???????? 5f }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   0f841dffffff         | je                  0xffffff23
            //   e8????????           |                     
            //   5f                   | pop                 edi

        $sequence_7 = { 80e920 ebe0 80a0a09e400000 40 }
            // n = 4, score = 200
            //   80e920               | sub                 cl, 0x20
            //   ebe0                 | jmp                 0xffffffe2
            //   80a0a09e400000       | and                 byte ptr [eax + 0x409ea0], 0
            //   40                   | inc                 eax

        $sequence_8 = { 81c408100000 c3 ff15???????? 6a00 ff15???????? 5f 5e }
            // n = 7, score = 200
            //   81c408100000         | add                 esp, 0x1008
            //   c3                   | ret                 
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 83c404 8bf0 33c0 89442414 8944241c }
            // n = 5, score = 200
            //   83c404               | add                 esp, 4
            //   8bf0                 | mov                 esi, eax
            //   33c0                 | xor                 eax, eax
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax

    condition:
        7 of them and filesize < 106496
}