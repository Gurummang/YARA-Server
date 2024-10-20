rule win_acehash_auto {

    meta:
        atk_type = "win.acehash."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.acehash."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acehash"
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
        $sequence_0 = { 4885c0 7420 488d1599dc0200 488bcb ff15???????? 488bc8 }
            // n = 6, score = 200
            //   4885c0               | mov                 eax, esp
            //   7420                 | dec                 esp
            //   488d1599dc0200       | sub                 eax, ecx
            //   488bcb               | jne                 0xae8
            //   ff15????????         |                     
            //   488bc8               | xor                 eax, eax

        $sequence_1 = { 85c0 0f85e6000000 4c8b470c 488b55d0 488b4f04 ff15???????? 8bd8 }
            // n = 7, score = 200
            //   85c0                 | mov                 byte ptr [ebx + 2], bl
            //   0f85e6000000         | mov                 byte ptr [ebx + 1], al
            //   4c8b470c             | movzx               eax, byte ptr [esp + 0x28]
            //   488b55d0             | mov                 byte ptr [ebx + 3], al
            //   488b4f04             | mov                 eax, ecx
            //   ff15????????         |                     
            //   8bd8                 | shr                 eax, 0x10

        $sequence_2 = { 488b7d98 8b742440 8b542458 41bb00020000 4c8d0d4e23feff 448a3f 4584ff }
            // n = 7, score = 200
            //   488b7d98             | dec                 ecx
            //   8b742440             | je                  0x1fa7
            //   8b542458             | dec                 ecx
            //   41bb00020000         | mov                 edi, ecx
            //   4c8d0d4e23feff       | inc                 ecx
            //   448a3f               | and                 eax, 7
            //   4584ff               | inc                 ecx

        $sequence_3 = { 7510 b810000000 488b5c2430 4883c420 5f c3 4885db }
            // n = 7, score = 200
            //   7510                 | lea                 ecx, [ebp - 0x80]
            //   b810000000           | mov                 ebx, eax
            //   488b5c2430           | test                eax, eax
            //   4883c420             | jne                 0x2063
            //   5f                   | lea                 edx, [eax + esi*4]
            //   c3                   | dec                 eax
            //   4885db               | mov                 esi, dword ptr [ebp + 0x77]

        $sequence_4 = { 85ff 0f8513ffffff 33c0 4c8b642450 4c8b6c2458 488b5c2460 4883c430 }
            // n = 7, score = 200
            //   85ff                 | inc                 ecx
            //   0f8513ffffff         | cmovg               eax, eax
            //   33c0                 | mov                 dword ptr [ecx], eax
            //   4c8b642450           | ret                 
            //   4c8b6c2458           | inc                 ecx
            //   488b5c2460           | shl                 ebx, 8
            //   4883c430             | inc                 esp

        $sequence_5 = { 442b8486a0e10300 4533d8 83bf800000000a 0f863c010000 8b4730 8b4f70 458d0c03 }
            // n = 7, score = 200
            //   442b8486a0e10300     | je                  0x453
            //   4533d8               | dec                 ecx
            //   83bf800000000a       | mov                 ecx, esi
            //   0f863c010000         | dec                 eax
            //   8b4730               | mov                 edx, dword ptr [esp + 0x48]
            //   8b4f70               | dec                 ebp
            //   458d0c03             | test                esi, esi

        $sequence_6 = { 8bc3 483bd0 0f871a050000 4c8d151995fdff 4403f2 4b8b8ceaa0511100 8a443108 }
            // n = 7, score = 200
            //   8bc3                 | inc                 ecx
            //   483bd0               | movzx               eax, byte ptr [ebx + 1]
            //   0f871a050000         | dec                 esp
            //   4c8d151995fdff       | lea                 eax, [ebx + 0x80]
            //   4403f2               | mov                 edx, 1
            //   4b8b8ceaa0511100     | dec                 eax
            //   8a443108             | mov                 ecx, edi

        $sequence_7 = { 8bfd 66895802 410fb78704100000 0fbfcb }
            // n = 4, score = 200
            //   8bfd                 | add                 edx, 0xc
            //   66895802             | dec                 eax
            //   410fb78704100000     | sar                 edx, 2
            //   0fbfcb               | dec                 eax

        $sequence_8 = { 7cda 440fbf4302 418bd4 488bce 468d048508000000 e8???????? 488d0d33240300 }
            // n = 7, score = 200
            //   7cda                 | xor                 ecx, ecx
            //   440fbf4302           | xor                 edx, eax
            //   418bd4               | mov                 ecx, 1
            //   488bce               | inc                 eax
            //   468d048508000000     | movzx               edx, ch
            //   e8????????           |                     
            //   488d0d33240300       | mov                 ecx, 1

        $sequence_9 = { 48833d????????00 488d0581900300 740f 3908 740e 4883c010 4883780800 }
            // n = 7, score = 200
            //   48833d????????00     |                     
            //   488d0581900300       | lea                 edx, [0x33b59]
            //   740f                 | dec                 eax
            //   3908                 | lea                 edx, [0x39860]
            //   740e                 | dec                 eax
            //   4883c010             | mov                 edx, dword ptr [ebx]
            //   4883780800           | dec                 eax

    condition:
        7 of them and filesize < 2318336
}