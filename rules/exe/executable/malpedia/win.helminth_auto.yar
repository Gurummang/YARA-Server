rule win_helminth_auto {

    meta:
        atk_type = "win.helminth."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.helminth."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.helminth"
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
        $sequence_0 = { a1???????? 68e8030000 8907 e8???????? }
            // n = 4, score = 300
            //   a1????????           |                     
            //   68e8030000           | push                0x3e8
            //   8907                 | mov                 dword ptr [edi], eax
            //   e8????????           |                     

        $sequence_1 = { 83e61f c1e606 57 8b3c9d70750110 8a4c3704 }
            // n = 5, score = 200
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   57                   | push                edi
            //   8b3c9d70750110       | mov                 edi, dword ptr [ebx*4 + 0x10017570]
            //   8a4c3704             | mov                 cl, byte ptr [edi + esi + 4]

        $sequence_2 = { 894c2408 8d9b00000000 668b02 83c202 6685c0 }
            // n = 5, score = 200
            //   894c2408             | mov                 dword ptr [esp + 8], ecx
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   668b02               | mov                 ax, word ptr [edx]
            //   83c202               | add                 edx, 2
            //   6685c0               | test                ax, ax

        $sequence_3 = { c1e106 899528e5ffff 53 8b149570750110 898d24e5ffff 8a5c1124 02db }
            // n = 7, score = 200
            //   c1e106               | shl                 ecx, 6
            //   899528e5ffff         | mov                 dword ptr [ebp - 0x1ad8], edx
            //   53                   | push                ebx
            //   8b149570750110       | mov                 edx, dword ptr [edx*4 + 0x10017570]
            //   898d24e5ffff         | mov                 dword ptr [ebp - 0x1adc], ecx
            //   8a5c1124             | mov                 bl, byte ptr [ecx + edx + 0x24]
            //   02db                 | add                 bl, bl

        $sequence_4 = { 85ff 0f84be000000 897de0 8b049d70750110 0500080000 3bf8 }
            // n = 6, score = 200
            //   85ff                 | test                edi, edi
            //   0f84be000000         | je                  0xc4
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   8b049d70750110       | mov                 eax, dword ptr [ebx*4 + 0x10017570]
            //   0500080000           | add                 eax, 0x800
            //   3bf8                 | cmp                 edi, eax

        $sequence_5 = { 03f2 eb5c 8b45f4 8b0c8570750110 f644190448 }
            // n = 5, score = 200
            //   03f2                 | add                 esi, edx
            //   eb5c                 | jmp                 0x5e
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b0c8570750110       | mov                 ecx, dword ptr [eax*4 + 0x10017570]
            //   f644190448           | test                byte ptr [ecx + ebx + 4], 0x48

        $sequence_6 = { 80c980 884c3704 8b0c9d70750110 8a443124 2481 }
            // n = 5, score = 200
            //   80c980               | or                  cl, 0x80
            //   884c3704             | mov                 byte ptr [edi + esi + 4], cl
            //   8b0c9d70750110       | mov                 ecx, dword ptr [ebx*4 + 0x10017570]
            //   8a443124             | mov                 al, byte ptr [ecx + esi + 0x24]
            //   2481                 | and                 al, 0x81

        $sequence_7 = { 2c2c 2c2c 232425???????? 2c2c 2c2c 2c2c }
            // n = 6, score = 200
            //   2c2c                 | sub                 al, 0x2c
            //   2c2c                 | sub                 al, 0x2c
            //   232425????????       |                     
            //   2c2c                 | sub                 al, 0x2c
            //   2c2c                 | sub                 al, 0x2c
            //   2c2c                 | sub                 al, 0x2c

        $sequence_8 = { e8???????? 59 6a64 ff15???????? 57 57 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   57                   | push                edi
            //   57                   | push                edi

        $sequence_9 = { 8bf9 897c2410 e8???????? 8bcf }
            // n = 4, score = 100
            //   8bf9                 | mov                 edi, ecx
            //   897c2410             | mov                 dword ptr [esp + 0x10], edi
            //   e8????????           |                     
            //   8bcf                 | mov                 ecx, edi

        $sequence_10 = { 8a02 8b9524e5ffff 8b0c9d28eb4100 88440a34 8b049d28eb4100 c744023801000000 }
            // n = 6, score = 100
            //   8a02                 | mov                 al, byte ptr [edx]
            //   8b9524e5ffff         | mov                 edx, dword ptr [ebp - 0x1adc]
            //   8b0c9d28eb4100       | mov                 ecx, dword ptr [ebx*4 + 0x41eb28]
            //   88440a34             | mov                 byte ptr [edx + ecx + 0x34], al
            //   8b049d28eb4100       | mov                 eax, dword ptr [ebx*4 + 0x41eb28]
            //   c744023801000000     | mov                 dword ptr [edx + eax + 0x38], 1

        $sequence_11 = { 663bc1 75f4 6a18 59 be???????? }
            // n = 5, score = 100
            //   663bc1               | cmp                 ax, cx
            //   75f4                 | jne                 0xfffffff6
            //   6a18                 | push                0x18
            //   59                   | pop                 ecx
            //   be????????           |                     

        $sequence_12 = { a1???????? eb0c c745e4a4ee4100 a1???????? 33db }
            // n = 5, score = 100
            //   a1????????           |                     
            //   eb0c                 | jmp                 0xe
            //   c745e4a4ee4100       | mov                 dword ptr [ebp - 0x1c], 0x41eea4
            //   a1????????           |                     
            //   33db                 | xor                 ebx, ebx

        $sequence_13 = { 83c102 663bc3 75f4 a1???????? 8bd7 }
            // n = 5, score = 100
            //   83c102               | add                 ecx, 2
            //   663bc3               | cmp                 ax, bx
            //   75f4                 | jne                 0xfffffff6
            //   a1????????           |                     
            //   8bd7                 | mov                 edx, edi

        $sequence_14 = { 6a03 68???????? 8d0c458ce44100 8bc1 2d???????? d1f8 }
            // n = 6, score = 100
            //   6a03                 | push                3
            //   68????????           |                     
            //   8d0c458ce44100       | lea                 ecx, [eax*2 + 0x41e48c]
            //   8bc1                 | mov                 eax, ecx
            //   2d????????           |                     
            //   d1f8                 | sar                 eax, 1

    condition:
        7 of them and filesize < 479232
}