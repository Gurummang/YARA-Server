rule win_hesperbot_auto {

    meta:
        atk_type = "win.hesperbot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hesperbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hesperbot"
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
        $sequence_0 = { 33f0 8b442440 0b442438 33cf 23442448 8b7c2444 8b5c2440 }
            // n = 7, score = 500
            //   33f0                 | xor                 esi, eax
            //   8b442440             | mov                 eax, dword ptr [esp + 0x40]
            //   0b442438             | or                  eax, dword ptr [esp + 0x38]
            //   33cf                 | xor                 ecx, edi
            //   23442448             | and                 eax, dword ptr [esp + 0x48]
            //   8b7c2444             | mov                 edi, dword ptr [esp + 0x44]
            //   8b5c2440             | mov                 ebx, dword ptr [esp + 0x40]

        $sequence_1 = { f60602 740e 8bc6 e8???????? 85c0 7403 8326fd }
            // n = 7, score = 500
            //   f60602               | test                byte ptr [esi], 2
            //   740e                 | je                  0x10
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5
            //   8326fd               | and                 dword ptr [esi], 0xfffffffd

        $sequence_2 = { 85f6 7454 817d0818040000 724b 57 8b3e }
            // n = 6, score = 500
            //   85f6                 | test                esi, esi
            //   7454                 | je                  0x56
            //   817d0818040000       | cmp                 dword ptr [ebp + 8], 0x418
            //   724b                 | jb                  0x4d
            //   57                   | push                edi
            //   8b3e                 | mov                 edi, dword ptr [esi]

        $sequence_3 = { 59 59 85c0 741e ff7510 8b450c 8d4ddc }
            // n = 7, score = 500
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   741e                 | je                  0x20
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]

        $sequence_4 = { 8d45ec b975382414 46 e8???????? 8d45ec 6a10 50 }
            // n = 7, score = 500
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   b975382414           | mov                 ecx, 0x14243875
            //   46                   | inc                 esi
            //   e8????????           |                     
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   6a10                 | push                0x10
            //   50                   | push                eax

        $sequence_5 = { 03f3 837f1800 7639 8b0e 03cb e8???????? 3b4508 }
            // n = 7, score = 500
            //   03f3                 | add                 esi, ebx
            //   837f1800             | cmp                 dword ptr [edi + 0x18], 0
            //   7639                 | jbe                 0x3b
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   03cb                 | add                 ecx, ebx
            //   e8????????           |                     
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]

        $sequence_6 = { 8b01 eb0b 8b5008 3b54240c }
            // n = 4, score = 500
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   eb0b                 | jmp                 0xd
            //   8b5008               | mov                 edx, dword ptr [eax + 8]
            //   3b54240c             | cmp                 edx, dword ptr [esp + 0xc]

        $sequence_7 = { c9 c3 64a130000000 c3 55 8bec 83ec48 }
            // n = 7, score = 500
            //   c9                   | leave               
            //   c3                   | ret                 
            //   64a130000000         | mov                 eax, dword ptr fs:[0x30]
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec48               | sub                 esp, 0x48

        $sequence_8 = { 56 33f6 85c0 741a 0fb71471 83fa41 720c }
            // n = 7, score = 500
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   85c0                 | test                eax, eax
            //   741a                 | je                  0x1c
            //   0fb71471             | movzx               edx, word ptr [ecx + esi*2]
            //   83fa41               | cmp                 edx, 0x41
            //   720c                 | jb                  0xe

        $sequence_9 = { 7308 e8???????? 33d2 42 }
            // n = 4, score = 500
            //   7308                 | jae                 0xa
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   42                   | inc                 edx

    condition:
        7 of them and filesize < 188416
}