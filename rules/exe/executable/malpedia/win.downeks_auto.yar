rule win_downeks_auto {

    meta:
        atk_type = "win.downeks."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.downeks."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.downeks"
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
        $sequence_0 = { e9???????? 8b8ddcfeffff 51 ff15???????? 8b8de0feffff 53 }
            // n = 6, score = 200
            //   e9????????           |                     
            //   8b8ddcfeffff         | mov                 ecx, dword ptr [ebp - 0x124]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b8de0feffff         | mov                 ecx, dword ptr [ebp - 0x120]
            //   53                   | push                ebx

        $sequence_1 = { c3 8b4108 c3 b8ccd00904 c3 8bff 55 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   8b4108               | mov                 eax, dword ptr [ecx + 8]
            //   c3                   | ret                 
            //   b8ccd00904           | mov                 eax, 0x409d0cc
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp

        $sequence_2 = { 8d4da0 e8???????? 8b4704 85c0 7409 83f8ff 7304 }
            // n = 7, score = 200
            //   8d4da0               | lea                 ecx, [ebp - 0x60]
            //   e8????????           |                     
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   83f8ff               | cmp                 eax, -1
            //   7304                 | jae                 6

        $sequence_3 = { e8???????? 8bd8 83c40c 85db 0f85cf000000 8b55c0 85d2 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83c40c               | add                 esp, 0xc
            //   85db                 | test                ebx, ebx
            //   0f85cf000000         | jne                 0xd5
            //   8b55c0               | mov                 edx, dword ptr [ebp - 0x40]
            //   85d2                 | test                edx, edx

        $sequence_4 = { 2bce 51 8bce 2b4d80 8d75a8 8d558c e8???????? }
            // n = 7, score = 200
            //   2bce                 | sub                 ecx, esi
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi
            //   2b4d80               | sub                 ecx, dword ptr [ebp - 0x80]
            //   8d75a8               | lea                 esi, [ebp - 0x58]
            //   8d558c               | lea                 edx, [ebp - 0x74]
            //   e8????????           |                     

        $sequence_5 = { e9???????? 8d75b4 e9???????? 8d75d0 e9???????? 8bb560ffffff e9???????? }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8d75b4               | lea                 esi, [ebp - 0x4c]
            //   e9????????           |                     
            //   8d75d0               | lea                 esi, [ebp - 0x30]
            //   e9????????           |                     
            //   8bb560ffffff         | mov                 esi, dword ptr [ebp - 0xa0]
            //   e9????????           |                     

        $sequence_6 = { c785e8faffff07000000 89b5e4faffff 668995d4faffff e8???????? 8975fc 80fb5c 740a }
            // n = 7, score = 200
            //   c785e8faffff07000000     | mov    dword ptr [ebp - 0x518], 7
            //   89b5e4faffff         | mov                 dword ptr [ebp - 0x51c], esi
            //   668995d4faffff       | mov                 word ptr [ebp - 0x52c], dx
            //   e8????????           |                     
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   80fb5c               | cmp                 bl, 0x5c
            //   740a                 | je                  0xc

        $sequence_7 = { c1ea08 0fb6d2 8b3c95a0c20804 0fb6d0 8b1495a0c60804 c1e808 0fb6c0 }
            // n = 7, score = 200
            //   c1ea08               | shr                 edx, 8
            //   0fb6d2               | movzx               edx, dl
            //   8b3c95a0c20804       | mov                 edi, dword ptr [edx*4 + 0x408c2a0]
            //   0fb6d0               | movzx               edx, al
            //   8b1495a0c60804       | mov                 edx, dword ptr [edx*4 + 0x408c6a0]
            //   c1e808               | shr                 eax, 8
            //   0fb6c0               | movzx               eax, al

        $sequence_8 = { ff15???????? 8bf0 83c42c 85f6 0f8547feffff 8b45f0 50 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83c42c               | add                 esp, 0x2c
            //   85f6                 | test                esi, esi
            //   0f8547feffff         | jne                 0xfffffe4d
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax

        $sequence_9 = { 7488 8b4d0c 833900 7502 8901 8b4d10 8b13 }
            // n = 7, score = 200
            //   7488                 | je                  0xffffff8a
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   833900               | cmp                 dword ptr [ecx], 0
            //   7502                 | jne                 4
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b13                 | mov                 edx, dword ptr [ebx]

    condition:
        7 of them and filesize < 1318912
}