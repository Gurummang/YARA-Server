rule win_dharma_auto {

    meta:
        atk_type = "win.dharma."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.dharma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dharma"
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
        $sequence_0 = { 8945e8 8b45ec 8b4808 8b55ec }
            // n = 4, score = 100
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]

        $sequence_1 = { 8b4824 8b5508 8b4218 8d0c48 51 68ff7f0000 }
            // n = 6, score = 100
            //   8b4824               | mov                 ecx, dword ptr [eax + 0x24]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4218               | mov                 eax, dword ptr [edx + 0x18]
            //   8d0c48               | lea                 ecx, [eax + ecx*2]
            //   51                   | push                ecx
            //   68ff7f0000           | push                0x7fff

        $sequence_2 = { 68???????? 6a00 6a00 e8???????? eb0e 8b4dfc 51 }
            // n = 7, score = 100
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   e8????????           |                     
            //   eb0e                 | jmp                 0x10
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx

        $sequence_3 = { 8b45e4 034530 8945e4 8b4dfc 034d30 894dfc 6a06 }
            // n = 7, score = 100
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   034530               | add                 eax, dword ptr [ebp + 0x30]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   034d30               | add                 ecx, dword ptr [ebp + 0x30]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   6a06                 | push                6

        $sequence_4 = { a1???????? 898574ffffff 6880000000 68???????? 8b8d74ffffff 51 68???????? }
            // n = 7, score = 100
            //   a1????????           |                     
            //   898574ffffff         | mov                 dword ptr [ebp - 0x8c], eax
            //   6880000000           | push                0x80
            //   68????????           |                     
            //   8b8d74ffffff         | mov                 ecx, dword ptr [ebp - 0x8c]
            //   51                   | push                ecx
            //   68????????           |                     

        $sequence_5 = { 8945fc 8b4d08 0fb711 d1fa 8955e0 8b45f8 c1e818 }
            // n = 7, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   0fb711               | movzx               edx, word ptr [ecx]
            //   d1fa                 | sar                 edx, 1
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   c1e818               | shr                 eax, 0x18

        $sequence_6 = { 741a 8b5508 83c22c 8b4dfc 8b8108000100 }
            // n = 5, score = 100
            //   741a                 | je                  0x1c
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83c22c               | add                 edx, 0x2c
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b8108000100         | mov                 eax, dword ptr [ecx + 0x10008]

        $sequence_7 = { 8b0c85b8bf4000 81e10000ff00 33d1 8b45f4 }
            // n = 4, score = 100
            //   8b0c85b8bf4000       | mov                 ecx, dword ptr [eax*4 + 0x40bfb8]
            //   81e10000ff00         | and                 ecx, 0xff0000
            //   33d1                 | xor                 edx, ecx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_8 = { d1f8 8d4c0002 51 e8???????? 83c404 8b55ec 8b4a08 }
            // n = 7, score = 100
            //   d1f8                 | sar                 eax, 1
            //   8d4c0002             | lea                 ecx, [eax + eax + 2]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8b4a08               | mov                 ecx, dword ptr [edx + 8]

        $sequence_9 = { 8b55f4 83c201 8955f4 eba3 8b45f8 50 e8???????? }
            // n = 7, score = 100
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   83c201               | add                 edx, 1
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   eba3                 | jmp                 0xffffffa5
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 204800
}