rule win_highnote_auto {

    meta:
        atk_type = "win.highnote."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.highnote."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.highnote"
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
        $sequence_0 = { b3a7 8cd7 a5 329ea1afa9a5 5d b5a5 }
            // n = 6, score = 200
            //   b3a7                 | mov                 bl, 0xa7
            //   8cd7                 | mov                 edi, ss
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   329ea1afa9a5         | xor                 bl, byte ptr [esi - 0x5a56505f]
            //   5d                   | pop                 ebp
            //   b5a5                 | mov                 ch, 0xa5

        $sequence_1 = { 2d620a682c fd 9d 8945ec 8945f0 8945f4 9c }
            // n = 7, score = 200
            //   2d620a682c           | sub                 eax, 0x2c680a62
            //   fd                   | std                 
            //   9d                   | popfd               
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   9c                   | pushfd              

        $sequence_2 = { 3665017cf341 14b0 63c5 ef d550 3362db }
            // n = 6, score = 200
            //   3665017cf341         | add                 dword ptr gs:[ebx + esi*8 + 0x41], edi
            //   14b0                 | adc                 al, 0xb0
            //   63c5                 | arpl                bp, ax
            //   ef                   | out                 dx, eax
            //   d550                 | aad                 0x50
            //   3362db               | xor                 esp, dword ptr [edx - 0x25]

        $sequence_3 = { 0fb6c9 8a1408 0fb6da 03de 81e3ff000080 }
            // n = 5, score = 200
            //   0fb6c9               | movzx               ecx, cl
            //   8a1408               | mov                 dl, byte ptr [eax + ecx]
            //   0fb6da               | movzx               ebx, dl
            //   03de                 | add                 ebx, esi
            //   81e3ff000080         | and                 ebx, 0x800000ff

        $sequence_4 = { 98 fd bfb47ea0c6 ddbb690cc1af 6595 fa 6a23 }
            // n = 7, score = 200
            //   98                   | cwde                
            //   fd                   | std                 
            //   bfb47ea0c6           | mov                 edi, 0xc6a07eb4
            //   ddbb690cc1af         | fnstsw              dword ptr [ebx - 0x503ef397]
            //   6595                 | xchg                eax, ebp
            //   fa                   | cli                 
            //   6a23                 | push                0x23

        $sequence_5 = { 115542 305421f0 d438 bd4dae2b31 b1f7 }
            // n = 5, score = 200
            //   115542               | adc                 dword ptr [ebp + 0x42], edx
            //   305421f0             | xor                 byte ptr [ecx - 0x10], dl
            //   d438                 | aam                 0x38
            //   bd4dae2b31           | mov                 ebp, 0x312bae4d
            //   b1f7                 | mov                 cl, 0xf7

        $sequence_6 = { 90 9e a4 3634a1 6594 2424 e230 }
            // n = 7, score = 200
            //   90                   | nop                 
            //   9e                   | sahf                
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   3634a1               | xor                 al, 0xa1
            //   6594                 | xchg                eax, esp
            //   2424                 | and                 al, 0x24
            //   e230                 | loop                0x32

        $sequence_7 = { 2ca7 33e6 7479 1e 0477 ed 7cb1 }
            // n = 7, score = 200
            //   2ca7                 | sub                 al, 0xa7
            //   33e6                 | xor                 esp, esi
            //   7479                 | je                  0x7b
            //   1e                   | push                ds
            //   0477                 | add                 al, 0x77
            //   ed                   | in                  eax, dx
            //   7cb1                 | jl                  0xffffffb3

        $sequence_8 = { 8636 35cfd6d703 b368 321e 4a 727d 51 }
            // n = 7, score = 200
            //   8636                 | xchg                byte ptr [esi], dh
            //   35cfd6d703           | xor                 eax, 0x3d7d6cf
            //   b368                 | mov                 bl, 0x68
            //   321e                 | xor                 bl, byte ptr [esi]
            //   4a                   | dec                 edx
            //   727d                 | jb                  0x7f
            //   51                   | push                ecx

        $sequence_9 = { 000b 2920 da927a3741d4 7e5b a7 5a 40 }
            // n = 7, score = 200
            //   000b                 | add                 byte ptr [ebx], cl
            //   2920                 | sub                 dword ptr [eax], esp
            //   da927a3741d4         | ficom               dword ptr [edx - 0x2bbec886]
            //   7e5b                 | jle                 0x5d
            //   a7                   | cmpsd               dword ptr [esi], dword ptr es:[edi]
            //   5a                   | pop                 edx
            //   40                   | inc                 eax

    condition:
        7 of them and filesize < 321536
}