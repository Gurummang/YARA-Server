rule win_vobfus_auto {

    meta:
        atk_type = "win.vobfus."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.vobfus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vobfus"
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
        $sequence_0 = { 8b5508 8b92e8000000 8b82841d0000 50 50 8b10 }
            // n = 6, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82841d0000         | mov                 eax, dword ptr [edx + 0x1d84]
            //   50                   | push                eax
            //   50                   | push                eax
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_1 = { 8b5508 8b92e8000000 8b825c1e0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b825c1e0000         | mov                 eax, dword ptr [edx + 0x1e5c]
            //   50                   | push                eax

        $sequence_2 = { 8bec 8b5508 8b92e8000000 8b82c8150000 }
            // n = 4, score = 200
            //   8bec                 | mov                 ebp, esp
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82c8150000         | mov                 eax, dword ptr [edx + 0x15c8]

        $sequence_3 = { 8b8220000000 50 50 8b10 ff5204 58 }
            // n = 6, score = 200
            //   8b8220000000         | mov                 eax, dword ptr [edx + 0x20]
            //   50                   | push                eax
            //   50                   | push                eax
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff5204               | call                dword ptr [edx + 4]
            //   58                   | pop                 eax

        $sequence_4 = { 8b5508 8b92e8000000 8b8200080000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b8200080000         | mov                 eax, dword ptr [edx + 0x800]
            //   50                   | push                eax

        $sequence_5 = { 8b5508 8b92e8000000 8b82b4230000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82b4230000         | mov                 eax, dword ptr [edx + 0x23b4]
            //   50                   | push                eax

        $sequence_6 = { 8b5508 8b92e8000000 8b82d0130000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82d0130000         | mov                 eax, dword ptr [edx + 0x13d0]
            //   50                   | push                eax

        $sequence_7 = { 8b5508 8b92e8000000 8b829c0e0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b829c0e0000         | mov                 eax, dword ptr [edx + 0xe9c]
            //   50                   | push                eax

        $sequence_8 = { f3ed ebf2 ed ec }
            // n = 4, score = 100
            //   f3ed                 | in                  eax, dx
            //   ebf2                 | jmp                 0xfffffff4
            //   ed                   | in                  eax, dx
            //   ec                   | in                  al, dx

        $sequence_9 = { ec f2ed ec f2ed ec f3ed }
            // n = 6, score = 100
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f3ed                 | in                  eax, dx

        $sequence_10 = { f2e8fae6d5f6 d2b5f2bb8ff3 ae 73f3 aa 5c f6ac4ff8b54ffb }
            // n = 7, score = 100
            //   f2e8fae6d5f6         | bnd call            0xf6d5e700
            //   d2b5f2bb8ff3         | sal                 byte ptr [ebp - 0xc70440e], cl
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   73f3                 | jae                 0xfffffff5
            //   aa                   | stosb               byte ptr es:[edi], al
            //   5c                   | pop                 esp
            //   f6ac4ff8b54ffb       | imul                byte ptr [edi + ecx*2 - 0x4b04a08]

        $sequence_11 = { 801800 0808 0006 3401 41 06 }
            // n = 6, score = 100
            //   801800               | sbb                 byte ptr [eax], 0
            //   0808                 | or                  byte ptr [eax], cl
            //   0006                 | add                 byte ptr [esi], al
            //   3401                 | xor                 al, 1
            //   41                   | inc                 ecx
            //   06                   | push                es

        $sequence_12 = { 7cc8 dc7acd e291 d2e8 }
            // n = 4, score = 100
            //   7cc8                 | jl                  0xffffffca
            //   dc7acd               | fdivr               qword ptr [edx - 0x33]
            //   e291                 | loop                0xffffff93
            //   d2e8                 | shr                 al, cl

        $sequence_13 = { 8631 96 0a7f25 7a43 92 9afc9e5780451f }
            // n = 6, score = 100
            //   8631                 | xchg                byte ptr [ecx], dh
            //   96                   | xchg                eax, esi
            //   0a7f25               | or                  bh, byte ptr [edi + 0x25]
            //   7a43                 | jp                  0x45
            //   92                   | xchg                eax, edx
            //   9afc9e5780451f       | lcall               0x1f45:0x80579efc

        $sequence_14 = { 0c38 a95bedb2e5 759e 3a9b423ceb9d 65be2dafffcd 3624e4 6bee88 }
            // n = 7, score = 100
            //   0c38                 | or                  al, 0x38
            //   a95bedb2e5           | test                eax, 0xe5b2ed5b
            //   759e                 | jne                 0xffffffa0
            //   3a9b423ceb9d         | cmp                 bl, byte ptr [ebx - 0x6214c3be]
            //   65be2dafffcd         | mov                 esi, 0xcdffaf2d
            //   3624e4               | and                 al, 0xe4
            //   6bee88               | imul                ebp, esi, -0x78

        $sequence_15 = { 4b ce 8ca4b11e13b793 73aa fa }
            // n = 5, score = 100
            //   4b                   | dec                 ebx
            //   ce                   | into                
            //   8ca4b11e13b793       | mov                 word ptr [ecx + esi*4 - 0x6c48ece2], fs
            //   73aa                 | jae                 0xffffffac
            //   fa                   | cli                 

        $sequence_16 = { 48 0008 78ff 0d50004900 3e3cff 46 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   0008                 | add                 byte ptr [eax], cl
            //   78ff                 | js                  1
            //   0d50004900           | or                  eax, 0x490050
            //   3e3cff               | cmp                 al, 0xff
            //   46                   | inc                 esi

        $sequence_17 = { 5c f6ac4ff8b54ffb c058fcca 61 }
            // n = 4, score = 100
            //   5c                   | pop                 esp
            //   f6ac4ff8b54ffb       | imul                byte ptr [edi + ecx*2 - 0x4b04a08]
            //   c058fcca             | rcr                 byte ptr [eax - 4], 0xca
            //   61                   | popal               

        $sequence_18 = { 46 14ff 0470 fe0a }
            // n = 4, score = 100
            //   46                   | inc                 esi
            //   14ff                 | adc                 al, 0xff
            //   0470                 | add                 al, 0x70
            //   fe0a                 | dec                 byte ptr [edx]

        $sequence_19 = { e752 47 625403a7 78f5 06 95 }
            // n = 6, score = 100
            //   e752                 | out                 0x52, eax
            //   47                   | inc                 edi
            //   625403a7             | bound               edx, qword ptr [ebx + eax - 0x59]
            //   78f5                 | js                  0xfffffff7
            //   06                   | push                es
            //   95                   | xchg                eax, ebp

        $sequence_20 = { 6c 74ff 801800 0808 }
            // n = 4, score = 100
            //   6c                   | insb                byte ptr es:[edi], dx
            //   74ff                 | je                  1
            //   801800               | sbb                 byte ptr [eax], 0
            //   0808                 | or                  byte ptr [eax], cl

        $sequence_21 = { b909dfd18c 9d 7454 2bcd 8ab411746337ed 80ab931e2e5e88 }
            // n = 6, score = 100
            //   b909dfd18c           | mov                 ecx, 0x8cd1df09
            //   9d                   | popfd               
            //   7454                 | je                  0x56
            //   2bcd                 | sub                 ecx, ebp
            //   8ab411746337ed       | mov                 dh, byte ptr [ecx + edx - 0x12c89c8c]
            //   80ab931e2e5e88       | sub                 byte ptr [ebx + 0x5e2e1e93], 0x88

        $sequence_22 = { c8ed9459 ef 60 226aa3 60 8907 6bdd97 }
            // n = 7, score = 100
            //   c8ed9459             | enter               -0x6b13, 0x59
            //   ef                   | out                 dx, eax
            //   60                   | pushal              
            //   226aa3               | and                 ch, byte ptr [edx - 0x5d]
            //   60                   | pushal              
            //   8907                 | mov                 dword ptr [edi], eax
            //   6bdd97               | imul                ebx, ebp, -0x69

    condition:
        7 of them and filesize < 409600
}