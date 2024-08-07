rule win_mm_core_auto {

    meta:
        atk_type = "win.mm_core."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mm_core."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mm_core"
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
        $sequence_0 = { 7458 57 8b7c240c 85ff 744e 6a40 6800300000 }
            // n = 7, score = 200
            //   7458                 | je                  0x5a
            //   57                   | push                edi
            //   8b7c240c             | mov                 edi, dword ptr [esp + 0xc]
            //   85ff                 | test                edi, edi
            //   744e                 | je                  0x50
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000

        $sequence_1 = { c1f805 8bf7 83e61f c1e606 03348540400110 c745e401000000 }
            // n = 6, score = 200
            //   c1f805               | sar                 eax, 5
            //   8bf7                 | mov                 esi, edi
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   03348540400110       | add                 esi, dword ptr [eax*4 + 0x10014040]
            //   c745e401000000       | mov                 dword ptr [ebp - 0x1c], 1

        $sequence_2 = { 8b45fc ff34c5e41c0110 53 57 e8???????? 83c40c 85c0 }
            // n = 7, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   ff34c5e41c0110       | push                dword ptr [eax*8 + 0x10011ce4]
            //   53                   | push                ebx
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax

        $sequence_3 = { 85f6 0f848d000000 8b0e 85c9 7442 8b5608 }
            // n = 6, score = 200
            //   85f6                 | test                esi, esi
            //   0f848d000000         | je                  0x93
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   85c9                 | test                ecx, ecx
            //   7442                 | je                  0x44
            //   8b5608               | mov                 edx, dword ptr [esi + 8]

        $sequence_4 = { 8b442424 8b4c242c 8938 8931 }
            // n = 4, score = 200
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   8b4c242c             | mov                 ecx, dword ptr [esp + 0x2c]
            //   8938                 | mov                 dword ptr [eax], edi
            //   8931                 | mov                 dword ptr [ecx], esi

        $sequence_5 = { 8955d4 8b45d4 8b4814 894ddc }
            // n = 4, score = 200
            //   8955d4               | mov                 dword ptr [ebp - 0x2c], edx
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   8b4814               | mov                 ecx, dword ptr [eax + 0x14]
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx

        $sequence_6 = { 8d4c244c 51 55 55 68???????? 68???????? }
            // n = 6, score = 200
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]
            //   51                   | push                ecx
            //   55                   | push                ebp
            //   55                   | push                ebp
            //   68????????           |                     
            //   68????????           |                     

        $sequence_7 = { 57 52 89842480000000 898c2484000000 89bc2488000000 e8???????? 83c40c }
            // n = 7, score = 200
            //   57                   | push                edi
            //   52                   | push                edx
            //   89842480000000       | mov                 dword ptr [esp + 0x80], eax
            //   898c2484000000       | mov                 dword ptr [esp + 0x84], ecx
            //   89bc2488000000       | mov                 dword ptr [esp + 0x88], edi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_8 = { e8???????? bb???????? 8d742434 e8???????? 8d9c24a8050000 8d742428 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   bb????????           |                     
            //   8d742434             | lea                 esi, [esp + 0x34]
            //   e8????????           |                     
            //   8d9c24a8050000       | lea                 ebx, [esp + 0x5a8]
            //   8d742428             | lea                 esi, [esp + 0x28]
            //   e8????????           |                     

        $sequence_9 = { 8b4dc4 0fb611 0355fc 8955fc 8b45c4 }
            // n = 5, score = 200
            //   8b4dc4               | mov                 ecx, dword ptr [ebp - 0x3c]
            //   0fb611               | movzx               edx, byte ptr [ecx]
            //   0355fc               | add                 edx, dword ptr [ebp - 4]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]

    condition:
        7 of them and filesize < 319488
}