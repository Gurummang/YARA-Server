rule win_startpage_auto {

    meta:
        atk_type = "win.startpage."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.startpage."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.startpage"
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
        $sequence_0 = { 8945ec 85db 740c 8b0b 85c9 7406 0fb701 }
            // n = 7, score = 200
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   85db                 | test                ebx, ebx
            //   740c                 | je                  0xe
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8
            //   0fb701               | movzx               eax, word ptr [ecx]

        $sequence_1 = { 83eb01 75f1 8b75f8 8b06 33c9 663b08 759d }
            // n = 7, score = 200
            //   83eb01               | sub                 ebx, 1
            //   75f1                 | jne                 0xfffffff3
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   33c9                 | xor                 ecx, ecx
            //   663b08               | cmp                 cx, word ptr [eax]
            //   759d                 | jne                 0xffffff9f

        $sequence_2 = { 75f5 2bd1 d1fa 5b 52 ff7508 8bcf }
            // n = 7, score = 200
            //   75f5                 | jne                 0xfffffff7
            //   2bd1                 | sub                 edx, ecx
            //   d1fa                 | sar                 edx, 1
            //   5b                   | pop                 ebx
            //   52                   | push                edx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bcf                 | mov                 ecx, edi

        $sequence_3 = { 8901 89742410 eb06 8931 8b742410 8b44241c 85c0 }
            // n = 7, score = 200
            //   8901                 | mov                 dword ptr [ecx], eax
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   eb06                 | jmp                 8
            //   8931                 | mov                 dword ptr [ecx], esi
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   85c0                 | test                eax, eax

        $sequence_4 = { 8bec a1???????? 85c0 740e 50 e8???????? 8325????????00 }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   740e                 | je                  0x10
            //   50                   | push                eax
            //   e8????????           |                     
            //   8325????????00       |                     

        $sequence_5 = { 722e 8b4dc0 40 3d00100000 721a f6c11f 759c }
            // n = 7, score = 200
            //   722e                 | jb                  0x30
            //   8b4dc0               | mov                 ecx, dword ptr [ebp - 0x40]
            //   40                   | inc                 eax
            //   3d00100000           | cmp                 eax, 0x1000
            //   721a                 | jb                  0x1c
            //   f6c11f               | test                cl, 0x1f
            //   759c                 | jne                 0xffffff9e

        $sequence_6 = { 8b03 8bfb 53 ff5004 8b7508 33c9 8bc3 }
            // n = 7, score = 200
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8bfb                 | mov                 edi, ebx
            //   53                   | push                ebx
            //   ff5004               | call                dword ptr [eax + 4]
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   8bc3                 | mov                 eax, ebx

        $sequence_7 = { e8???????? 59 c645fc01 8b8de0feffff 83c1f0 e8???????? 51 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8b8de0feffff         | mov                 ecx, dword ptr [ebp - 0x120]
            //   83c1f0               | add                 ecx, -0x10
            //   e8????????           |                     
            //   51                   | push                ecx

        $sequence_8 = { 755f 8a0a 8d4201 8907 80f975 7553 8b4db8 }
            // n = 7, score = 200
            //   755f                 | jne                 0x61
            //   8a0a                 | mov                 cl, byte ptr [edx]
            //   8d4201               | lea                 eax, [edx + 1]
            //   8907                 | mov                 dword ptr [edi], eax
            //   80f975               | cmp                 cl, 0x75
            //   7553                 | jne                 0x55
            //   8b4db8               | mov                 ecx, dword ptr [ebp - 0x48]

        $sequence_9 = { 8907 50 50 8945fc ff35???????? ff31 }
            // n = 6, score = 200
            //   8907                 | mov                 dword ptr [edi], eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ff35????????         |                     
            //   ff31                 | push                dword ptr [ecx]

    condition:
        7 of them and filesize < 2277376
}