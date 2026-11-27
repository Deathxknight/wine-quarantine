import "math"

rule ELF_High_Entropy
{
    meta:
    description = "ELF with unusually high entropy (packed/encrypted)"
    author      = "wq-sandbox"
    severity    = "medium"
    condition:
    uint32(0) == 0x464C457F
    and filesize > 10KB and filesize < 50MB
    and math.entropy(0, filesize) > 7.2
}

rule ELF_Obfuscated_Ransom_String
{
    meta:
    description = "ELF carries a ransomware-note string under a single-byte XOR key"
    author      = "wq-sandbox"
    severity    = "high"
    strings:
    $s1 = "YOUR FILES" xor(0x00-0xff)
    $s2 = "ENCRYPTED"  xor(0x00-0xff)
    $s3 = "PAY 1 BTC"  xor(0x00-0xff)
    condition:
    uint32(0) == 0x464C457F
    and filesize < 10MB
    and 2 of them
}
