rule win_liteduke_auto {

    meta:
        atk_type = "win.liteduke."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.liteduke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.liteduke"
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
        $sequence_0 = { ff7508 ff15???????? ff75fc ff15???????? 5b 5e }
            // n = 6, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_1 = { 6800010000 ff15???????? c3 68???????? ff15???????? }
            // n = 5, score = 200
            //   6800010000           | push                0x100
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_2 = { 5b 5e 5f 8b45d8 c9 c20400 55 }
            // n = 7, score = 200
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   55                   | push                ebp

        $sequence_3 = { 41 83f904 7cdd 5f 5e }
            // n = 5, score = 200
            //   41                   | inc                 ecx
            //   83f904               | cmp                 ecx, 4
            //   7cdd                 | jl                  0xffffffdf
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { c9 c20800 55 89e5 ff7508 e8???????? }
            // n = 6, score = 200
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_5 = { c20c00 c70101000000 61 c9 c20c00 c70100000000 61 }
            // n = 7, score = 200
            //   c20c00               | ret                 0xc
            //   c70101000000         | mov                 dword ptr [ecx], 1
            //   61                   | popal               
            //   c9                   | leave               
            //   c20c00               | ret                 0xc
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   61                   | popal               

        $sequence_6 = { c1c006 243f 3c3e 7205 c0e002 2c0e 2c04 }
            // n = 7, score = 200
            //   c1c006               | rol                 eax, 6
            //   243f                 | and                 al, 0x3f
            //   3c3e                 | cmp                 al, 0x3e
            //   7205                 | jb                  7
            //   c0e002               | shl                 al, 2
            //   2c0e                 | sub                 al, 0xe
            //   2c04                 | sub                 al, 4

        $sequence_7 = { 46 8a06 8807 46 43 41 42 }
            // n = 7, score = 200
            //   46                   | inc                 esi
            //   8a06                 | mov                 al, byte ptr [esi]
            //   8807                 | mov                 byte ptr [edi], al
            //   46                   | inc                 esi
            //   43                   | inc                 ebx
            //   41                   | inc                 ecx
            //   42                   | inc                 edx

        $sequence_8 = { b800000000 8a03 c1e804 83f809 7f05 83c030 eb03 }
            // n = 7, score = 200
            //   b800000000           | mov                 eax, 0
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   c1e804               | shr                 eax, 4
            //   83f809               | cmp                 eax, 9
            //   7f05                 | jg                  7
            //   83c030               | add                 eax, 0x30
            //   eb03                 | jmp                 5

        $sequence_9 = { 56 e8???????? 83c40c ff750c 56 e8???????? 83c408 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

    condition:
        7 of them and filesize < 1171456
}