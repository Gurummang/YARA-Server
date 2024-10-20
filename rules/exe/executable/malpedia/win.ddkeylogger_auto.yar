rule win_ddkeylogger_auto {

    meta:
        atk_type = "win.ddkeylogger."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ddkeylogger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ddkeylogger"
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
        $sequence_0 = { 8bf7 83e61f c1e606 03348580ee4500 }
            // n = 4, score = 200
            //   8bf7                 | mov                 esi, edi
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   03348580ee4500       | add                 esi, dword ptr [eax*4 + 0x45ee80]

        $sequence_1 = { 51 894df4 8955fc 8945f8 e8???????? 83c408 }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_2 = { 8bc8 c1e902 f3a5 8bc8 8d95e8faffff 83e103 52 }
            // n = 7, score = 200
            //   8bc8                 | mov                 ecx, eax
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   8d95e8faffff         | lea                 edx, [ebp - 0x518]
            //   83e103               | and                 ecx, 3
            //   52                   | push                edx

        $sequence_3 = { 0fb64f08 80cbff d2e3 40 f6d3 205c30ff 0fb64f08 }
            // n = 7, score = 200
            //   0fb64f08             | movzx               ecx, byte ptr [edi + 8]
            //   80cbff               | or                  bl, 0xff
            //   d2e3                 | shl                 bl, cl
            //   40                   | inc                 eax
            //   f6d3                 | not                 bl
            //   205c30ff             | and                 byte ptr [eax + esi - 1], bl
            //   0fb64f08             | movzx               ecx, byte ptr [edi + 8]

        $sequence_4 = { 0405 c3 f6c20c 7409 f6c208 0f95c0 }
            // n = 6, score = 200
            //   0405                 | add                 al, 5
            //   c3                   | ret                 
            //   f6c20c               | test                dl, 0xc
            //   7409                 | je                  0xb
            //   f6c208               | test                dl, 8
            //   0f95c0               | setne               al

        $sequence_5 = { 52 50 8b81e0000000 ffd0 837df804 75e8 }
            // n = 6, score = 200
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b81e0000000         | mov                 eax, dword ptr [ecx + 0xe0]
            //   ffd0                 | call                eax
            //   837df804             | cmp                 dword ptr [ebp - 8], 4
            //   75e8                 | jne                 0xffffffea

        $sequence_6 = { c745fc00000000 e8???????? 83c40c 8d85ccfaffff 50 8d8df0fdffff 51 }
            // n = 7, score = 200
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d85ccfaffff         | lea                 eax, [ebp - 0x534]
            //   50                   | push                eax
            //   8d8df0fdffff         | lea                 ecx, [ebp - 0x210]
            //   51                   | push                ecx

        $sequence_7 = { 50 57 ffd3 8945bc 8d45c8 50 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd3                 | call                ebx
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   50                   | push                eax

        $sequence_8 = { ff248d4cf74000 8d48cf 80f908 7706 6a03 }
            // n = 5, score = 200
            //   ff248d4cf74000       | jmp                 dword ptr [ecx*4 + 0x40f74c]
            //   8d48cf               | lea                 ecx, [eax - 0x31]
            //   80f908               | cmp                 cl, 8
            //   7706                 | ja                  8
            //   6a03                 | push                3

        $sequence_9 = { 6bc930 8975e0 8db1c0624100 8975e4 }
            // n = 4, score = 200
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   8db1c0624100         | lea                 esi, [ecx + 0x4162c0]
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi

    condition:
        7 of them and filesize < 808960
}