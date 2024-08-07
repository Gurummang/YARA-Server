rule win_nullmixer_auto {

    meta:
        atk_type = "win.nullmixer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nullmixer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nullmixer"
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
        $sequence_0 = { 6683fa05 0f8726010000 83e857 83f8ff 0f85d0fcffff 8d7600 }
            // n = 6, score = 100
            //   6683fa05             | cmp                 dx, 5
            //   0f8726010000         | ja                  0x12c
            //   83e857               | sub                 eax, 0x57
            //   83f8ff               | cmp                 eax, -1
            //   0f85d0fcffff         | jne                 0xfffffcd6
            //   8d7600               | lea                 esi, [esi]

        $sequence_1 = { c7442404???????? c70424???????? c705????????d09d4a00 e8???????? c705????????01000000 83ec08 89d9 }
            // n = 7, score = 100
            //   c7442404????????     |                     
            //   c70424????????       |                     
            //   c705????????d09d4a00     |     
            //   e8????????           |                     
            //   c705????????01000000     |     
            //   83ec08               | sub                 esp, 8
            //   89d9                 | mov                 ecx, ebx

        $sequence_2 = { a3???????? 8d8568feffff c7442408???????? c7442404???????? 890424 e8???????? 8d8568feffff }
            // n = 7, score = 100
            //   a3????????           |                     
            //   8d8568feffff         | lea                 eax, [ebp - 0x198]
            //   c7442408????????     |                     
            //   c7442404????????     |                     
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8d8568feffff         | lea                 eax, [ebp - 0x198]

        $sequence_3 = { 8901 8d44241f 89442408 e8???????? 31d2 c7400800000000 83c00c }
            // n = 7, score = 100
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8d44241f             | lea                 eax, [esp + 0x1f]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   e8????????           |                     
            //   31d2                 | xor                 edx, edx
            //   c7400800000000       | mov                 dword ptr [eax + 8], 0
            //   83c00c               | add                 eax, 0xc

        $sequence_4 = { c784245001000000000000 31c9 e9???????? 8b8c2450010000 e8???????? b8ffffffff 8b94245c010000 }
            // n = 7, score = 100
            //   c784245001000000000000     | mov    dword ptr [esp + 0x150], 0
            //   31c9                 | xor                 ecx, ecx
            //   e9????????           |                     
            //   8b8c2450010000       | mov                 ecx, dword ptr [esp + 0x150]
            //   e8????????           |                     
            //   b8ffffffff           | mov                 eax, 0xffffffff
            //   8b94245c010000       | mov                 edx, dword ptr [esp + 0x15c]

        $sequence_5 = { 01c9 896c2404 894c2408 890424 e8???????? e9???????? 8b442448 }
            // n = 7, score = 100
            //   01c9                 | add                 ecx, ecx
            //   896c2404             | mov                 dword ptr [esp + 4], ebp
            //   894c2408             | mov                 dword ptr [esp + 8], ecx
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   e9????????           |                     
            //   8b442448             | mov                 eax, dword ptr [esp + 0x48]

        $sequence_6 = { 398424d0000000 0f8430050000 8b06 c744240400000000 89f1 0fb75502 891424 }
            // n = 7, score = 100
            //   398424d0000000       | cmp                 dword ptr [esp + 0xd0], eax
            //   0f8430050000         | je                  0x536
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   89f1                 | mov                 ecx, esi
            //   0fb75502             | movzx               edx, word ptr [ebp + 2]
            //   891424               | mov                 dword ptr [esp], edx

        $sequence_7 = { 83f90f 0f4fc8 8b45a8 3975ac 19f8 0f82d0000000 8b55bc }
            // n = 7, score = 100
            //   83f90f               | cmp                 ecx, 0xf
            //   0f4fc8               | cmovg               ecx, eax
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   3975ac               | cmp                 dword ptr [ebp - 0x54], esi
            //   19f8                 | sbb                 eax, edi
            //   0f82d0000000         | jb                  0xd6
            //   8b55bc               | mov                 edx, dword ptr [ebp - 0x44]

        $sequence_8 = { 83ec04 837d8010 8d75b4 0f94c2 8b4808 39f9 894d8c }
            // n = 7, score = 100
            //   83ec04               | sub                 esp, 4
            //   837d8010             | cmp                 dword ptr [ebp - 0x80], 0x10
            //   8d75b4               | lea                 esi, [ebp - 0x4c]
            //   0f94c2               | sete                dl
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]
            //   39f9                 | cmp                 ecx, edi
            //   894d8c               | mov                 dword ptr [ebp - 0x74], ecx

        $sequence_9 = { 89f1 e8???????? 8b06 89f1 c704242b000000 ff5018 52 }
            // n = 7, score = 100
            //   89f1                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   89f1                 | mov                 ecx, esi
            //   c704242b000000       | mov                 dword ptr [esp], 0x2b
            //   ff5018               | call                dword ptr [eax + 0x18]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 2351104
}