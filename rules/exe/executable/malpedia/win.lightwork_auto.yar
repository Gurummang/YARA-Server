rule win_lightwork_auto {

    meta:
        atk_type = "win.lightwork."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lightwork."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lightwork"
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
        $sequence_0 = { 0fb7442462 89442404 8b442464 890424 e8???????? }
            // n = 5, score = 100
            //   0fb7442462           | movzx               eax, word ptr [esp + 0x62]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   8b442464             | mov                 eax, dword ptr [esp + 0x64]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     

        $sequence_1 = { c3 55 89e5 83ec38 8b4508 83c07c 8945f0 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   83ec38               | sub                 esp, 0x38
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c07c               | add                 eax, 0x7c
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_2 = { e8???????? 894508 837d0800 740b 8b4508 890424 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   740b                 | je                  0xd
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_3 = { c645f700 807df700 0f85b1feffff 8b45ec 890424 e8???????? 8b45f0 }
            // n = 7, score = 100
            //   c645f700             | mov                 byte ptr [ebp - 9], 0
            //   807df700             | cmp                 byte ptr [ebp - 9], 0
            //   0f85b1feffff         | jne                 0xfffffeb7
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_4 = { c9 c3 55 89e5 83ec28 c7042408000000 e8???????? }
            // n = 7, score = 100
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   83ec28               | sub                 esp, 0x28
            //   c7042408000000       | mov                 dword ptr [esp], 8
            //   e8????????           |                     

        $sequence_5 = { 8b4014 83c003 8945f4 8b450c }
            // n = 4, score = 100
            //   8b4014               | mov                 eax, dword ptr [eax + 0x14]
            //   83c003               | add                 eax, 3
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_6 = { 894508 837d0800 741e 8b4508 890424 e8???????? }
            // n = 6, score = 100
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   741e                 | je                  0x20
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     

        $sequence_7 = { 8b45f8 83c002 01d0 0fb600 0fb6c0 c1e010 0145fc }
            // n = 7, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83c002               | add                 eax, 2
            //   01d0                 | add                 eax, edx
            //   0fb600               | movzx               eax, byte ptr [eax]
            //   0fb6c0               | movzx               eax, al
            //   c1e010               | shl                 eax, 0x10
            //   0145fc               | add                 dword ptr [ebp - 4], eax

        $sequence_8 = { e8???????? 8b4508 c780a401000000000000 90 c9 c3 55 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   c780a401000000000000     | mov    dword ptr [eax + 0x1a4], 0
            //   90                   | nop                 
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_9 = { 894508 837d0800 740b 8b4508 890424 e8???????? 8b4508 }
            // n = 7, score = 100
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   740b                 | je                  0xd
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 1132544
}