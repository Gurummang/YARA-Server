rule win_open_carrot_auto {

    meta:
        atk_type = "win.open_carrot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.open_carrot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.open_carrot"
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
        $sequence_0 = { b910000000 e8???????? 4889442430 c700ffffffff 48c74008ffffffff 8b4c2438 8908 }
            // n = 7, score = 100
            //   b910000000           | dec                 ebp
            //   e8????????           |                     
            //   4889442430           | movzx               edx, word ptr [edx]
            //   c700ffffffff         | dec                 ecx
            //   48c74008ffffffff     | mov                 ecx, ebp
            //   8b4c2438             | dec                 ecx
            //   8908                 | add                 ecx, 0xa

        $sequence_1 = { b9c8dcfb75 ffc1 c1e106 83e9ff 83c101 6807ab8f5e 4c893424 }
            // n = 7, score = 100
            //   b9c8dcfb75           | dec                 eax
            //   ffc1                 | add                 ecx, ebp
            //   c1e106               | pop                 edx
            //   83e9ff               | dec                 eax
            //   83c101               | mov                 dword ptr [ecx], edx
            //   6807ab8f5e           | dec                 ecx
            //   4c893424             | mov                 ecx, 0x12

        $sequence_2 = { ffd0 eb05 bd01000000 440fb6e5 443bed 7c7a 488b15???????? }
            // n = 7, score = 100
            //   ffd0                 | test                eax, eax
            //   eb05                 | je                  0x5d2
            //   bd01000000           | xor                 edx, edx
            //   440fb6e5             | dec                 eax
            //   443bed               | mov                 ecx, eax
            //   7c7a                 | dec                 eax
            //   488b15????????       |                     

        $sequence_3 = { 8bc3 e9???????? 41b805000000 488d153c9a1800 488bcf e8???????? 85c0 }
            // n = 7, score = 100
            //   8bc3                 | cmp                 dword ptr [edi], edi
            //   e9????????           |                     
            //   41b805000000         | dec                 ecx
            //   488d153c9a1800       | mov                 ecx, 0x12
            //   488bcf               | dec                 ecx
            //   e8????????           |                     
            //   85c0                 | mov                 esi, edi

        $sequence_4 = { ffcf 488d9512070000 4903d4 4c63c7 664289b445100f0000 e8???????? 6639b510170000 }
            // n = 7, score = 100
            //   ffcf                 | mov                 dword ptr [esp + 0x20], 4
            //   488d9512070000       | xor                 edx, edx
            //   4903d4               | dec                 eax
            //   4c63c7               | test                eax, eax
            //   664289b445100f0000     | je    0x18d8
            //   e8????????           |                     
            //   6639b510170000       | dec                 eax

        $sequence_5 = { 4881cb3f000000 48c7c000020000 4981c46f000000 4809f0 4d0fb72424 4881c204000000 4809c6 }
            // n = 7, score = 100
            //   4881cb3f000000       | jne                 0x736
            //   48c7c000020000       | dec                 esp
            //   4981c46f000000       | lea                 ecx, [0xb7b58]
            //   4809f0               | dec                 ecx
            //   4d0fb72424           | mov                 edi, ecx
            //   4881c204000000       | inc                 esp
            //   4809c6               | mov                 ecx, ecx

        $sequence_6 = { 83fe07 7772 4c8d0dad8df9ff 4863c6 418b8481f0750600 4903c1 ffe0 }
            // n = 7, score = 100
            //   83fe07               | inc                 esp
            //   7772                 | movzx               eax, al
            //   4c8d0dad8df9ff       | inc                 ecx
            //   4863c6               | mov                 edx, ebx
            //   418b8481f0750600     | inc                 ecx
            //   4903c1               | mov                 ecx, 0x20
            //   ffe0                 | inc                 ecx

        $sequence_7 = { e9???????? 488d05de191400 894c2420 4c8d2dabb30f00 89742424 eb42 488d05aeb30f00 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488d05de191400       | dec                 eax
            //   894c2420             | add                 ebp, 0x6adf3bf4
            //   4c8d2dabb30f00       | dec                 eax
            //   89742424             | add                 ebp, 0x67fd13ed
            //   eb42                 | dec                 eax
            //   488d05aeb30f00       | add                 ebp, 0x4fdf254f

        $sequence_8 = { 4c8d0d91850b00 8d4a98 448d42ef e8???????? e9???????? 4c8b4310 488bd7 }
            // n = 7, score = 100
            //   4c8d0d91850b00       | mov                 word ptr [ebx + ecx + 4], ax
            //   8d4a98               | dec                 eax
            //   448d42ef             | lea                 ebx, [ebx + 2]
            //   e8????????           |                     
            //   e9????????           |                     
            //   4c8b4310             | test                ax, ax
            //   488bd7               | jne                 0x948

        $sequence_9 = { 7422 41b8a3000000 488d15c7ff0900 e8???????? 48898380000000 4885c0 0f842f010000 }
            // n = 7, score = 100
            //   7422                 | pop                 ebx
            //   41b8a3000000         | ret                 
            //   488d15c7ff0900       | dec                 eax
            //   e8????????           |                     
            //   48898380000000       | sub                 ebx, eax
            //   4885c0               | dec                 esp
            //   0f842f010000         | mov                 dword ptr [esp + 0x20], edi

    condition:
        7 of them and filesize < 8377344
}