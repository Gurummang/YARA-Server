rule win_lemonduck_auto {

    meta:
        atk_type = "win.lemonduck."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lemonduck."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lemonduck"
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
        $sequence_0 = { 41c1e018 42330c22 450bc8 46334c2204 4433d9 410fb64625 4533d1 }
            // n = 7, score = 100
            //   41c1e018             | inc                 ecx
            //   42330c22             | mov                 esi, dword ptr [edx + ecx*4 + 0x169550]
            //   450bc8               | inc                 eax
            //   46334c2204           | movzx               ecx, bh
            //   4433d9               | inc                 ebp
            //   410fb64625           | mov                 esp, dword ptr [edx + eax*4 + 0x169550]
            //   4533d1               | inc                 ecx

        $sequence_1 = { 488b7c2430 33c0 488983a0000000 488983a8000000 488983b0000000 488983b8000000 488983c0000000 }
            // n = 7, score = 100
            //   488b7c2430           | cmova               eax, edx
            //   33c0                 | add                 al, cl
            //   488983a0000000       | inc                 ecx
            //   488983a8000000       | mov                 byte ptr [ecx + 2], al
            //   488983b0000000       | inc                 ecx
            //   488983b8000000       | movzx               ecx, byte ptr [ebp + 1]
            //   488983c0000000       | and                 cl, 0xf

        $sequence_2 = { 418bc0 80f909 410f47c2 02c1 41884102 410fb64d01 80e10f }
            // n = 7, score = 100
            //   418bc0               | dec                 eax
            //   80f909               | sub                 eax, ecx
            //   410f47c2             | dec                 eax
            //   02c1                 | add                 eax, -8
            //   41884102             | dec                 eax
            //   410fb64d01           | cmp                 eax, 0x1f
            //   80e10f               | ja                  0xa9

        $sequence_3 = { 488b89d8000000 48896c2438 4889742440 4883f9ff 7414 ff15???????? 8b4758 }
            // n = 7, score = 100
            //   488b89d8000000       | inc                 ecx
            //   48896c2438           | shr                 ecx, 8
            //   4889742440           | inc                 ecx
            //   4883f9ff             | movzx               eax, bh
            //   7414                 | inc                 ecx
            //   ff15????????         |                     
            //   8b4758               | shr                 edi, 8

        $sequence_4 = { 488d15d2280a00 488bcb ff15???????? 488905???????? 4885c0 0f8474010000 488d159a280a00 }
            // n = 7, score = 100
            //   488d15d2280a00       | inc                 ecx
            //   488bcb               | mov                 eax, dword ptr [ebx + 0x1c]
            //   ff15????????         |                     
            //   488905????????       |                     
            //   4885c0               | dec                 eax
            //   0f8474010000         | and                 edx, eax
            //   488d159a280a00       | dec                 edx

        $sequence_5 = { 488d05c6ba0000 488905???????? 488d0558c70000 488905???????? 488d05bad20000 488905???????? 488d054ce30000 }
            // n = 7, score = 100
            //   488d05c6ba0000       | test                eax, eax
            //   488905????????       |                     
            //   488d0558c70000       | je                  0x187
            //   488905????????       |                     
            //   488d05bad20000       | dec                 eax
            //   488905????????       |                     
            //   488d054ce30000       | lea                 edx, [0xa289a]

        $sequence_6 = { 41c1e908 410fb6c7 41c1ef08 418bb48a50951600 400fb6cf 458ba48250951600 410fb6c6 }
            // n = 7, score = 100
            //   41c1e908             | mov                 edx, 0x1004f
            //   410fb6c7             | nop                 
            //   41c1ef08             | dec                 eax
            //   418bb48a50951600     | lea                 eax, [0xbac6]
            //   400fb6cf             | dec                 eax
            //   458ba48250951600     | lea                 eax, [0xc758]
            //   410fb6c6             | dec                 eax

        $sequence_7 = { 482bc1 4883c0f8 4883f81f 0f8798000000 ba4f000100 e8???????? 90 }
            // n = 7, score = 100
            //   482bc1               | mov                 eax, dword ptr [edx + eax]
            //   4883c0f8             | dec                 eax
            //   4883f81f             | lea                 edx, [0xa28d2]
            //   0f8798000000         | dec                 eax
            //   ba4f000100           | mov                 ecx, ebx
            //   e8????????           |                     
            //   90                   | dec                 eax

    condition:
        7 of them and filesize < 10011648
}