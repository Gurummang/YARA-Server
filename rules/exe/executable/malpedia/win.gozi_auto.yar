rule win_gozi_auto {

    meta:
        atk_type = "win.gozi."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.gozi."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gozi"
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
        $sequence_0 = { 8b4dfc f3a4 b0e9 aa }
            // n = 4, score = 100
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   b0e9                 | mov                 al, 0xe9
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_1 = { ee 7f7b 36110b 33745571 de7e75 cd18 4a }
            // n = 7, score = 100
            //   ee                   | out                 dx, al
            //   7f7b                 | jg                  0x7d
            //   36110b               | adc                 dword ptr ss:[ebx], ecx
            //   33745571             | xor                 esi, dword ptr [ebp + edx*2 + 0x71]
            //   de7e75               | fidivr              word ptr [esi + 0x75]
            //   cd18                 | int                 0x18
            //   4a                   | dec                 edx

        $sequence_2 = { 3327 72e7 3ebb4a68d947 d93e 257296bc4a 1b6b61 9f }
            // n = 7, score = 100
            //   3327                 | xor                 esp, dword ptr [edi]
            //   72e7                 | jb                  0xffffffe9
            //   3ebb4a68d947         | mov                 ebx, 0x47d9684a
            //   d93e                 | fnstcw              word ptr [esi]
            //   257296bc4a           | and                 eax, 0x4abc9672
            //   1b6b61               | sbb                 ebp, dword ptr [ebx + 0x61]
            //   9f                   | lahf                

        $sequence_3 = { e8???????? 0bc0 7522 6a01 6a00 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   0bc0                 | or                  eax, eax
            //   7522                 | jne                 0x24
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_4 = { 2bfb 8b5518 8b12 6a00 }
            // n = 4, score = 100
            //   2bfb                 | sub                 edi, ebx
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   6a00                 | push                0

        $sequence_5 = { 4e b64e 0fc0d6 69d5920d9cef }
            // n = 4, score = 100
            //   4e                   | dec                 esi
            //   b64e                 | mov                 dh, 0x4e
            //   0fc0d6               | xadd                dh, dl
            //   69d5920d9cef         | imul                edx, ebp, 0xef9c0d92

        $sequence_6 = { 0fadce 80eede c0ca12 2af4 8af4 }
            // n = 5, score = 100
            //   0fadce               | shrd                esi, ecx, cl
            //   80eede               | sub                 dh, 0xde
            //   c0ca12               | ror                 dl, 0x12
            //   2af4                 | sub                 dh, ah
            //   8af4                 | mov                 dh, ah

        $sequence_7 = { 894598 50 e8???????? 8b4650 8b7c0704 }
            // n = 5, score = 100
            //   894598               | mov                 dword ptr [ebp - 0x68], eax
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4650               | mov                 eax, dword ptr [esi + 0x50]
            //   8b7c0704             | mov                 edi, dword ptr [edi + eax + 4]

        $sequence_8 = { 83c101 894df4 8b55ec 83ea02 3955f4 0f8d45040000 }
            // n = 6, score = 100
            //   83c101               | add                 ecx, 1
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   83ea02               | sub                 edx, 2
            //   3955f4               | cmp                 dword ptr [ebp - 0xc], edx
            //   0f8d45040000         | jge                 0x44b

        $sequence_9 = { 94 6e 8ee1 54 }
            // n = 4, score = 100
            //   94                   | xchg                eax, esp
            //   6e                   | outsb               dx, byte ptr [esi]
            //   8ee1                 | mov                 fs, ecx
            //   54                   | push                esp

        $sequence_10 = { 7516 c78554ffffff06000000 c78558ffffff00000000 eb14 }
            // n = 4, score = 100
            //   7516                 | jne                 0x18
            //   c78554ffffff06000000     | mov    dword ptr [ebp - 0xac], 6
            //   c78558ffffff00000000     | mov    dword ptr [ebp - 0xa8], 0
            //   eb14                 | jmp                 0x16

        $sequence_11 = { bf???????? 8bdf c70747494638 66c747043761 83c706 8b450c }
            // n = 6, score = 100
            //   bf????????           |                     
            //   8bdf                 | mov                 ebx, edi
            //   c70747494638         | mov                 dword ptr [edi], 0x38464947
            //   66c747043761         | mov                 word ptr [edi + 4], 0x6137
            //   83c706               | add                 edi, 6
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_12 = { c9 50 0c73 0e 96 3b5375 }
            // n = 6, score = 100
            //   c9                   | leave               
            //   50                   | push                eax
            //   0c73                 | or                  al, 0x73
            //   0e                   | push                cs
            //   96                   | xchg                eax, esi
            //   3b5375               | cmp                 edx, dword ptr [ebx + 0x75]

        $sequence_13 = { ffd7 03f0 56 53 33f6 56 }
            // n = 6, score = 100
            //   ffd7                 | call                edi
            //   03f0                 | add                 esi, eax
            //   56                   | push                esi
            //   53                   | push                ebx
            //   33f6                 | xor                 esi, esi
            //   56                   | push                esi

        $sequence_14 = { ad b710 2dc7ce5bbb d6 b6c6 }
            // n = 5, score = 100
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   b710                 | mov                 bh, 0x10
            //   2dc7ce5bbb           | sub                 eax, 0xbb5bcec7
            //   d6                   | salc                
            //   b6c6                 | mov                 dh, 0xc6

        $sequence_15 = { ff75e4 ffd0 c3 6a68 68???????? e8???????? }
            // n = 6, score = 100
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   ffd0                 | call                eax
            //   c3                   | ret                 
            //   6a68                 | push                0x68
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_16 = { 0f8229feffff 5f 5e 5b c9 c21000 }
            // n = 6, score = 100
            //   0f8229feffff         | jb                  0xfffffe2f
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c21000               | ret                 0x10

        $sequence_17 = { c9 c20800 6a00 8d87950c0000 }
            // n = 4, score = 100
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   6a00                 | push                0
            //   8d87950c0000         | lea                 eax, [edi + 0xc95]

        $sequence_18 = { 84c1 0fb3ea f6c1ba 0fce }
            // n = 4, score = 100
            //   84c1                 | test                cl, al
            //   0fb3ea               | btr                 edx, ebp
            //   f6c1ba               | test                cl, 0xba
            //   0fce                 | bswap               esi

        $sequence_19 = { 96 3b5375 60 d3e0 90 48 }
            // n = 6, score = 100
            //   96                   | xchg                eax, esi
            //   3b5375               | cmp                 edx, dword ptr [ebx + 0x75]
            //   60                   | pushal              
            //   d3e0                 | shl                 eax, cl
            //   90                   | nop                 
            //   48                   | dec                 eax

        $sequence_20 = { 69d5ca659407 f6de c645ff61 a1???????? 8b0d???????? 6a00 }
            // n = 6, score = 100
            //   69d5ca659407         | imul                edx, ebp, 0x79465ca
            //   f6de                 | neg                 dh
            //   c645ff61             | mov                 byte ptr [ebp - 1], 0x61
            //   a1????????           |                     
            //   8b0d????????         |                     
            //   6a00                 | push                0

        $sequence_21 = { 83c101 894d90 0fb755e4 52 8b4590 }
            // n = 5, score = 100
            //   83c101               | add                 ecx, 1
            //   894d90               | mov                 dword ptr [ebp - 0x70], ecx
            //   0fb755e4             | movzx               edx, word ptr [ebp - 0x1c]
            //   52                   | push                edx
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]

        $sequence_22 = { b87e8da638 e022 3a56b9 036890 2b02 9a102a6715fb53 }
            // n = 6, score = 100
            //   b87e8da638           | mov                 eax, 0x38a68d7e
            //   e022                 | loopne              0x24
            //   3a56b9               | cmp                 dl, byte ptr [esi - 0x47]
            //   036890               | add                 ebp, dword ptr [eax - 0x70]
            //   2b02                 | sub                 eax, dword ptr [edx]
            //   9a102a6715fb53       | lcall               0x53fb:0x15672a10

        $sequence_23 = { dc6f1b 95 bf633629a8 02738f }
            // n = 4, score = 100
            //   dc6f1b               | fsubr               qword ptr [edi + 0x1b]
            //   95                   | xchg                eax, ebp
            //   bf633629a8           | mov                 edi, 0xa8293663
            //   02738f               | add                 dh, byte ptr [ebx - 0x71]

        $sequence_24 = { 83bd54ffffff03 7c0a c78554ffffff00000000 eb95 33c0 8b55f4 }
            // n = 6, score = 100
            //   83bd54ffffff03       | cmp                 dword ptr [ebp - 0xac], 3
            //   7c0a                 | jl                  0xc
            //   c78554ffffff00000000     | mov    dword ptr [ebp - 0xac], 0
            //   eb95                 | jmp                 0xffffff97
            //   33c0                 | xor                 eax, eax
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_25 = { 0fbe4415ec 8b8d4cffffff 038d58ffffff 0fbe11 33d0 8b854cffffff }
            // n = 6, score = 100
            //   0fbe4415ec           | movsx               eax, byte ptr [ebp + edx - 0x14]
            //   8b8d4cffffff         | mov                 ecx, dword ptr [ebp - 0xb4]
            //   038d58ffffff         | add                 ecx, dword ptr [ebp - 0xa8]
            //   0fbe11               | movsx               edx, byte ptr [ecx]
            //   33d0                 | xor                 edx, eax
            //   8b854cffffff         | mov                 eax, dword ptr [ebp - 0xb4]

        $sequence_26 = { 41 4e 75ea 5e }
            // n = 4, score = 100
            //   41                   | inc                 ecx
            //   4e                   | dec                 esi
            //   75ea                 | jne                 0xffffffec
            //   5e                   | pop                 esi

        $sequence_27 = { 0f8447010000 83f8ff 0f843e010000 682000cc00 56 }
            // n = 5, score = 100
            //   0f8447010000         | je                  0x14d
            //   83f8ff               | cmp                 eax, -1
            //   0f843e010000         | je                  0x144
            //   682000cc00           | push                0xcc0020
            //   56                   | push                esi

        $sequence_28 = { 837df800 75c7 ff75fc e8???????? c9 }
            // n = 5, score = 100
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   75c7                 | jne                 0xffffffc9
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   c9                   | leave               

        $sequence_29 = { 0fb3ce 86d6 2af4 b252 b0ca c745fc00000000 }
            // n = 6, score = 100
            //   0fb3ce               | btr                 esi, ecx
            //   86d6                 | xchg                dh, dl
            //   2af4                 | sub                 dh, ah
            //   b252                 | mov                 dl, 0x52
            //   b0ca                 | mov                 al, 0xca
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_30 = { e8???????? 59 8bf0 89b5e0f2ffff }
            // n = 4, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8bf0                 | mov                 esi, eax
            //   89b5e0f2ffff         | mov                 dword ptr [ebp - 0xd20], esi

        $sequence_31 = { 85c0 7404 8365f800 85f6 7407 8b06 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7404                 | je                  6
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   85f6                 | test                esi, esi
            //   7407                 | je                  9
            //   8b06                 | mov                 eax, dword ptr [esi]

    condition:
        7 of them and filesize < 568320
}