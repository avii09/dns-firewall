rule Suspicious_Domain_Keywords
{
    meta:
        author = "Avantika Kesarwani"
        description = "Matches domain names containing known malicious or suspicious keywords."
        last_modified = "2025-05-08"
        category = "keyword match"
    
    strings:
        $a1 = "funyfile"
        $a2 = "1312services"
        $a3 = "smartpano"
        $a4 = "panel357375"
        $a5 = "chalks.000webhostapp"
        $a6 = "smart-vnc"
        $a7 = "downloadfile"
        $a11 = "pleasurecanbesafe"

    condition:
        any of them
}

rule Potential_DGA_Domain
{
    meta:
        author = "Avantika Kesarwani"
        description = "Detects domains that resemble algorithmically generated domains (DGAs)."
        last_modified = "2025-05-08"
        category = "regex pattern"
    
    strings:
        $dga1 = /[a-z]{6,12}\d{2,4}\.[a-z]{2,}/
        $dga2 = /[a-z]{8,}[0-9]{1,3}\.(top|pro|xyz|info|app|store|online)/ nocase
        

    condition:
        any of them
}

rule Suspicious_TLDs
{
    meta:
        author = "Avantika Kesarwani"
        description = "Flags domains that use frequently abused or low-reputation TLDs."
        last_modified = "2025-05-08"
        category = "tld pattern"
    
    strings:
        $tld1 = ".xyz"
        $tld2 = ".top"
        $tld4 = ".store"
        $tld5 = ".ru"
        $tld6 = ".pro"
        $tld7 = ".bio"
        $tld8 = ".bond"
        $tld9 = ".sbs"
        $tld10 = ".ink"
        $tld11 = ".su"
        $tld12 = ".cool"
        $tld13 = ".online"

    condition:
        any of them
}

rule Heuristic_FastFlux_Pattern
{
    meta:
        author = "Avantika Kesarwani"
        description = "Matches patterns commonly observed in fast-flux or dynamic infrastructure setups."
        last_modified = "2025-05-08"
        category = "heuristics"
    
    strings:
        $ff1 = "000webhostapp.com"
        $ff2 = "panel"
        $ff3 = /[a-z]{5,}[0-9]{3,}\.pro/
        $ff4 = /([a-z0-9]{10,20})\.app/
        $ff5 = /sync\.[a-z\-]{5,20}\.com/
        $ff6 = /smart.*\.top/
        $ff7 = /.*hiddenvnc\.com/

    condition:
        any of them
}
