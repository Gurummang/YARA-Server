rule win_skipper_auto {

    meta:
        atk_type = "win.skipper."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.skipper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.skipper"
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
        $sequence_0 = { 6a00 6a00 6a03 68???????? 68???????? 6a50 }
            // n = 6, score = 600
            //   6a00                 | dec                 eax
            //   6a00                 | mov                 dword ptr [ebx + eax], ecx
            //   6a03                 | dec                 eax
            //   68????????           |                     
            //   68????????           |                     
            //   6a50                 | add                 ecx, 0x30

        $sequence_1 = { 59 5d c3 55 8bec 33c0 50 }
            // n = 7, score = 500
            //   59                   | mov                 byte ptr [ebp + eax - 0x110], cl
            //   5d                   | movzx               edx, byte ptr [ebp - 4]
            //   c3                   | mov                 al, byte ptr [ebp - 0x111]
            //   55                   | mov                 byte ptr [ebp + edx - 0x110], al
            //   8bec                 | add                 edx, dword ptr [ebp - 4]
            //   33c0                 | and                 edx, 0x800000ff
            //   50                   | jns                 0x10

        $sequence_2 = { e8???????? 6804010000 e8???????? 6804010000 8bf8 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   6804010000           | push                0x64
            //   e8????????           |                     
            //   6804010000           | push                edx
            //   8bf8                 | push                eax

        $sequence_3 = { ff15???????? 6a00 6a00 6a00 6a00 68???????? 68???????? }
            // n = 7, score = 500
            //   ff15????????         |                     
            //   6a00                 | push                eax
            //   6a00                 | add                 esp, 4
            //   6a00                 | push                0
            //   6a00                 | push                0x64
            //   68????????           |                     
            //   68????????           |                     

        $sequence_4 = { e8???????? 6a04 e8???????? 8bf8 57 6a04 68???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   6a04                 | dec                 edx
            //   e8????????           |                     
            //   8bf8                 | push                ecx
            //   57                   | push                0xb
            //   6a04                 | push                edx
            //   68????????           |                     

        $sequence_5 = { 0fb6c3 03c8 81e1ff000080 7908 49 81c900ffffff 41 }
            // n = 7, score = 400
            //   0fb6c3               | mov                 dword ptr [ebp - 0x120], eax
            //   03c8                 | cmp                 dword ptr [ebp - 0x120], 0x100
            //   81e1ff000080         | jmp                 0xffffffd2
            //   7908                 | mov                 dword ptr [ebp - 0x118], 0
            //   49                   | mov                 dword ptr [ebp - 0x120], 0
            //   81c900ffffff         | jmp                 0x25
            //   41                   | mov                 eax, dword ptr [ebp - 0x120]

        $sequence_6 = { 8b4d08 0fb68405fcfeffff 320439 47 8847ff 4e 0f8568ffffff }
            // n = 7, score = 400
            //   8b4d08               | mov                 dword ptr [ebp - 0x124], ecx
            //   0fb68405fcfeffff     | mov                 edx, dword ptr [ebp - 0x124]
            //   320439               | cmp                 edx, dword ptr [ebp + 0x14]
            //   47                   | jge                 0xde
            //   8847ff               | mov                 eax, dword ptr [ebp - 8]
            //   4e                   | mov                 eax, dword ptr [ebp - 0x120]
            //   0f8568ffffff         | add                 eax, 1

        $sequence_7 = { 7c0e 0fba25????????01 0f824a0e0000 57 8bf9 83fa04 7231 }
            // n = 7, score = 400
            //   7c0e                 | movzx               edx, dl
            //   0fba25????????01     |                     
            //   0f824a0e0000         | mov                 al, byte ptr [ebp + edx - 0x110]
            //   57                   | mov                 byte ptr [ebp - 0x112], al
            //   8bf9                 | mov                 ecx, dword ptr [ebp + 0x10]
            //   83fa04               | add                 ecx, dword ptr [ebp - 0x124]
            //   7231                 | movsx               edx, byte ptr [ecx]

        $sequence_8 = { e8???????? 83c404 6a00 6a64 52 50 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   83c404               | lea                 eax, [eax + 1]
            //   6a00                 | jne                 4
            //   6a64                 | dec                 eax
            //   52                   | lea                 eax, [0x9aa5]
            //   50                   | je                  0x26

        $sequence_9 = { 8a85effeffff 888415f0feffff e9???????? c785dcfeffff00000000 }
            // n = 4, score = 200
            //   8a85effeffff         | xor                 byte ptr [ecx + edx + 0x24], al
            //   888415f0feffff       | mov                 esi, dword ptr [edi]
            //   e9????????           |                     
            //   c785dcfeffff00000000     | lea    ecx, [ebp + 0x20]

        $sequence_10 = { 898ddcfeffff 8b95dcfeffff 3b5514 0f8dcf000000 8b45f8 }
            // n = 5, score = 200
            //   898ddcfeffff         | jge                 0x1d
            //   8b95dcfeffff         | dec                 ecx
            //   3b5514               | or                  ecx, 0xffffff00
            //   0f8dcf000000         | push                0
            //   8b45f8               | push                0

        $sequence_11 = { 0fb6d2 8a8415f0feffff 8885eefeffff 8b4d10 038ddcfeffff 0fbe11 }
            // n = 6, score = 200
            //   0fb6d2               | jne                 0x16
            //   8a8415f0feffff       | jle                 0x94
            //   8885eefeffff         | dec                 ecx
            //   8b4d10               | sub                 edi, ebx
            //   038ddcfeffff         | inc                 ecx
            //   0fbe11               | and                 ecx, 0x800000ff

        $sequence_12 = { c1e81f 03d0 418bc1 8d1492 }
            // n = 4, score = 200
            //   c1e81f               | inc                 ecx
            //   03d0                 | movzx               edx, byte ptr [eax]
            //   418bc1               | inc                 ecx
            //   8d1492               | add                 edx, ecx

        $sequence_13 = { 0fb602 418800 44880a 410fb610 4103d1 }
            // n = 5, score = 200
            //   0fb602               | movzx               eax, byte ptr [edx]
            //   418800               | inc                 ecx
            //   44880a               | mov                 byte ptr [eax], al
            //   410fb610             | inc                 esp
            //   4103d1               | mov                 byte ptr [edx], cl

        $sequence_14 = { 81e2ff000080 7908 4a 81ca00ffffff 42 0fb6d2 8a8415f0feffff }
            // n = 7, score = 200
            //   81e2ff000080         | mov                 byte ptr [edi + 0xa], cl
            //   7908                 | movzx               edx, al
            //   4a                   | test                edx, edx
            //   81ca00ffffff         | je                  0x10
            //   42                   | mov                 dword ptr [ebp - 0x12c], 0x43a
            //   0fb6d2               | jmp                 0x1a
            //   8a8415f0feffff       | mov                 dword ptr [ebp - 0x12c], 0x1fffff

        $sequence_15 = { 51 6a0b 68???????? 8b15???????? 52 68???????? e8???????? }
            // n = 7, score = 200
            //   51                   | lea                 ecx, [ebp - 0xa0]
            //   6a0b                 | push                ecx
            //   68????????           |                     
            //   8b15????????         |                     
            //   52                   | cmp                 dword ptr [ebp - 0x9c], 5
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_16 = { 0fb645f8 8a8c15f0feffff 888c05f0feffff 0fb655fc 8a85effeffff }
            // n = 5, score = 200
            //   0fb645f8             | lea                 esi, [esi*8 + 0x23a070]
            //   8a8c15f0feffff       | cmp                 dword ptr [esi], ebx
            //   888c05f0feffff       | je                  0x23
            //   0fb655fc             | mov                 dword ptr [edi + 4], edx
            //   8a85effeffff         | mov                 word ptr [edi + 8], ax

        $sequence_17 = { 33c9 4963e9 498bf8 488d1424 448bd1 8bc1 0f1f840000000000 }
            // n = 7, score = 200
            //   33c9                 | shr                 eax, 0x1f
            //   4963e9               | add                 edx, eax
            //   498bf8               | inc                 ecx
            //   488d1424             | mov                 eax, ecx
            //   448bd1               | lea                 edx, [edx + edx*4]
            //   8bc1                 | xor                 ecx, ecx
            //   0f1f840000000000     | dec                 ecx

        $sequence_18 = { 4181c800ffffff 41ffc0 410fb6c0 488d1424 41ffc1 4803d0 48ffc3 }
            // n = 7, score = 200
            //   4181c800ffffff       | inc                 esp
            //   41ffc0               | add                 edx, edx
            //   410fb6c0             | inc                 ecx
            //   488d1424             | and                 edx, 0x800000ff
            //   41ffc1               | dec                 eax
            //   4803d0               | mov                 dword ptr [esp + 0x10], ebp
            //   48ffc3               | dec                 eax

        $sequence_19 = { 81c900ffffff ffc1 4863c1 0fb61404 4403d2 4181e2ff000080 }
            // n = 6, score = 200
            //   81c900ffffff         | mov                 edx, ecx
            //   ffc1                 | mov                 eax, ecx
            //   4863c1               | nop                 dword ptr [eax + eax]
            //   0fb61404             | add                 edx, eax
            //   4403d2               | inc                 ecx
            //   4181e2ff000080       | mov                 eax, ecx

        $sequence_20 = { 0fb6c2 49ffc3 0fb61404 4232541fff }
            // n = 4, score = 200
            //   0fb6c2               | mov                 byte ptr [ebx - 1], dl
            //   49ffc3               | dec                 eax
            //   0fb61404             | dec                 ebx
            //   4232541fff           | jne                 0xffffff87

        $sequence_21 = { 48896c2410 4889742418 48897c2420 4156 4881ec10010000 488b05???????? 4833c4 }
            // n = 7, score = 200
            //   48896c2410           | lea                 edx, [edx + edx*4]
            //   4889742418           | add                 edx, edx
            //   48897c2420           | sub                 eax, edx
            //   4156                 | dec                 eax
            //   4881ec10010000       | arpl                ax, dx
            //   488b05????????       |                     
            //   4833c4               | or                  ecx, 0xffffff00

        $sequence_22 = { 8b85e0feffff 83c001 8985e0feffff 81bde0feffff00010000 }
            // n = 4, score = 200
            //   8b85e0feffff         | push                3
            //   83c001               | push                0x50
            //   8985e0feffff         | push                0
            //   81bde0feffff00010000     | push    3

        $sequence_23 = { 4232541fff 418853ff 48ffcb 0f8575ffffff }
            // n = 4, score = 200
            //   4232541fff           | inc                 ecx
            //   418853ff             | dec                 eax
            //   48ffcb               | arpl                cx, ax
            //   0f8575ffffff         | movzx               edx, byte ptr [esp + eax]

        $sequence_24 = { 81ec24010000 a1???????? 33c5 8945f4 c745f800000000 }
            // n = 5, score = 200
            //   81ec24010000         | shl                 edx, 6
            //   a1????????           |                     
            //   33c5                 | mov                 al, byte ptr [ecx + edx + 0x24]
            //   8945f4               | xor                 al, byte ptr [ebp - 2]
            //   c745f800000000       | and                 al, 0x7f

        $sequence_25 = { 3d02010000 7513 8b4d08 e8???????? 68e8030000 ff15???????? }
            // n = 6, score = 100
            //   3d02010000           | mov                 byte ptr [edi - 1], al
            //   7513                 | dec                 esi
            //   8b4d08               | jne                 0xffffff7e
            //   e8????????           |                     
            //   68e8030000           | movzx               eax, bl
            //   ff15????????         |                     

        $sequence_26 = { 7528 48833d????????00 741e 488d0de59b0000 e8???????? 85c0 740e }
            // n = 7, score = 100
            //   7528                 | inc                 ebx
            //   48833d????????00     |                     
            //   741e                 | movzx               edx, byte ptr [esp + eax]
            //   488d0de59b0000       | inc                 edx
            //   e8????????           |                     
            //   85c0                 | xor                 dl, byte ptr [edi + ebx - 1]
            //   740e                 | inc                 ecx

        $sequence_27 = { 895704 66a1???????? 66894708 8a0d???????? 884f0a e8???????? 0fb6d0 }
            // n = 7, score = 100
            //   895704               | mov                 eax, 0x104
            //   66a1????????         |                     
            //   66894708             | dec                 eax
            //   8a0d????????         |                     
            //   884f0a               | mov                 edx, ebx
            //   e8????????           |                     
            //   0fb6d0               | dec                 eax

        $sequence_28 = { 85d2 740c c785d4feffff3a040000 eb0a c785d4feffffffff1f00 }
            // n = 5, score = 100
            //   85d2                 | mov                 ecx, edi
            //   740c                 | dec                 eax
            //   c785d4feffff3a040000     | lea    esi, [ebx + 0x128]
            //   eb0a                 | dec                 eax
            //   c785d4feffffffff1f00     | lea    edi, [ebx + 0x28]

        $sequence_29 = { 68???????? 68???????? 8d4d20 0f434d20 68bb010000 51 50 }
            // n = 7, score = 100
            //   68????????           |                     
            //   68????????           |                     
            //   8d4d20               | mov                 byte ptr [esp + 0x13], 0
            //   0f434d20             | push                0x104
            //   68bb010000           | push                3
            //   51                   | push                0x50
            //   50                   | push                0

        $sequence_30 = { ffb5b0faffff e9???????? 8d8580faffff 50 6a00 ffb590faffff }
            // n = 6, score = 100
            //   ffb5b0faffff         | push                3
            //   e9????????           |                     
            //   8d8580faffff         | push                0x50
            //   50                   | push                0
            //   6a00                 | push                0
            //   ffb590faffff         | push                3

        $sequence_31 = { 33c0 e9???????? 8975e4 33c0 39b8b8a62300 0f8491000000 }
            // n = 6, score = 100
            //   33c0                 | mov                 ebp, 6
            //   e9????????           |                     
            //   8975e4               | dec                 eax
            //   33c0                 | lea                 eax, [0xad1d]
            //   39b8b8a62300         | dec                 eax
            //   0f8491000000         | cmp                 dword ptr [edi - 0x10], eax

        $sequence_32 = { 488bc3 488d15cfa30000 48c1f805 83e11f 488b04c2 486bc958 }
            // n = 6, score = 100
            //   488bc3               | lea                 edx, [esp]
            //   488d15cfa30000       | inc                 ecx
            //   48c1f805             | inc                 ecx
            //   83e11f               | dec                 eax
            //   488b04c2             | add                 edx, eax
            //   486bc958             | dec                 eax

        $sequence_33 = { 48ffc8 90 80780100 488d4001 75f6 }
            // n = 5, score = 100
            //   48ffc8               | inc                 ebx
            //   90                   | movzx               edx, byte ptr [esp + eax]
            //   80780100             | inc                 edx
            //   488d4001             | xor                 dl, byte ptr [edi + ebx - 1]
            //   75f6                 | inc                 ecx

        $sequence_34 = { ff15???????? 41b900800000 41b804010000 488bd3 488bcf ff15???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   41b900800000         | inc                 ebx
            //   41b804010000         | inc                 ecx
            //   488bd3               | mov                 byte ptr [eax], al
            //   488bcf               | inc                 esp
            //   ff15????????         |                     

        $sequence_35 = { b81a000000 eb23 488d0da39a0000 48890c03 4883c130 }
            // n = 5, score = 100
            //   b81a000000           | mov                 byte ptr [ebx - 1], dl
            //   eb23                 | dec                 eax
            //   488d0da39a0000       | dec                 ebx
            //   48890c03             | movzx               eax, dl
            //   4883c130             | dec                 ecx

        $sequence_36 = { 8b0c85606d4100 c1e206 8a441124 3245fe 247f 30441124 8b37 }
            // n = 7, score = 100
            //   8b0c85606d4100       | add                 ecx, eax
            //   c1e206               | and                 ecx, 0x800000ff
            //   8a441124             | jns                 0x12
            //   3245fe               | dec                 ecx
            //   247f                 | or                  ecx, 0xffffff00
            //   30441124             | inc                 ecx
            //   8b37                 | push                0x104

        $sequence_37 = { 8b7508 8d34f570a02300 391e 7404 }
            // n = 4, score = 100
            //   8b7508               | imul                ecx, ecx, 0x58
            //   8d34f570a02300       | inc                 ecx
            //   391e                 | mov                 ecx, 0x8000
            //   7404                 | inc                 ecx

        $sequence_38 = { e8???????? 488db328010000 488d7b28 bd06000000 488d051dad0000 483947f0 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   488db328010000       | mov                 byte ptr [edx], cl
            //   488d7b28             | inc                 ecx
            //   bd06000000           | movzx               edx, byte ptr [eax]
            //   488d051dad0000       | inc                 ecx
            //   483947f0             | add                 edx, ecx

        $sequence_39 = { e8???????? 59 8945e4 8b7508 c7465cd8812300 33ff 47 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | dec                 eax
            //   8945e4               | lea                 ebx, [0xa524]
            //   8b7508               | mov                 ebp, edi
            //   c7465cd8812300       | dec                 eax
            //   33ff                 | mov                 esi, dword ptr [ebx]
            //   47                   | dec                 eax

        $sequence_40 = { 8bff 55 8bec 8b4508 ff34c570a02300 }
            // n = 5, score = 100
            //   8bff                 | dec                 eax
            //   55                   | mov                 eax, ebx
            //   8bec                 | dec                 eax
            //   8b4508               | lea                 edx, [0xa3cf]
            //   ff34c570a02300       | dec                 eax

        $sequence_41 = { 8a80b4a62300 08443b1d 0fb64601 47 3bf8 }
            // n = 5, score = 100
            //   8a80b4a62300         | sar                 eax, 5
            //   08443b1d             | and                 ecx, 0x1f
            //   0fb64601             | dec                 eax
            //   47                   | mov                 eax, dword ptr [edx + eax*8]
            //   3bf8                 | dec                 eax

        $sequence_42 = { 488d1d24a50000 8bef 488b33 4885f6 }
            // n = 4, score = 100
            //   488d1d24a50000       | and                 edx, 0x800000ff
            //   8bef                 | jge                 0x22
            //   488b33               | movzx               eax, dl
            //   4885f6               | dec                 ecx

        $sequence_43 = { a3???????? a1???????? c705????????66162300 8935???????? a3???????? ff15???????? }
            // n = 6, score = 100
            //   a3????????           |                     
            //   a1????????           |                     
            //   c705????????66162300     |     
            //   8935????????         |                     
            //   a3????????           |                     
            //   ff15????????         |                     

        $sequence_44 = { 488d05a59a0000 740f 3908 740e 4883c010 4883780800 }
            // n = 6, score = 100
            //   488d05a59a0000       | inc                 edx
            //   740f                 | movzx               eax, cl
            //   3908                 | dec                 esp
            //   740e                 | lea                 eax, [esp]
            //   4883c010             | dec                 eax
            //   4883780800           | lea                 edx, [esp]

    condition:
        7 of them and filesize < 262144
}