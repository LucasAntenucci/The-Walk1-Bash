rule Findyou_HAHA
{
	meta:
		author = "henry"
		description = "Detectador de ransom"
		date = "15/09"

	strings:
		$a0 = "icacls"
		$s0 = "kernel32.dll" wide ascii nocase
		$s1 = "advapi32.dll" wide ascii nocase
		$s2 = "user32.dll" wide ascii nocase
		
	condition:
		any of ($a*) and 2 of ($s*)
}

rule TESTE_FILE {

meta:
 	description = "file teste"

strings:

	$s1 = ".java"
	$s2 = ".pdf"
	$s3 = ".mov"
	$s4 = ".zip"
	$s5 = ".mp4"
	$s6 = ".doc"
	$s7 = ".docx"
	$s8 = ".jpg"
	$s9 = ".pptx"
	$s10 = ".mkv"
	$s11 = ".png"
	$s12 = ".txt"
	$s13 = ".iso"
	$s14 = ".mp3"
	$s15 = ".docb"
	$s16 = ".docm"
	$s17 = ".cmd"
	$s18 = ".7z"
	$s19 = ".rar"
	$s20 = ".jpeg"	
	
condition:

	$s1 and $s2 and $s3 and $s4 and $s5 and $s6 and $s7 and $s8 and $s9 and $s10 and $s11 and $s12 and $s13 and $s14 and $s15 and $s16 and $s17 and $s18 and $s19 and $s20

}

rule Rule_Malware
{
	meta:
		author = "leleo e theo"
		description = "Dtetectar por strings"
		date = "15/09"
	strings:
		$a = "vssadmin"
		$b = "delete"
		$c = "shadows"
                $d = "all"
		$e = "quiet"


	condition:
		$a and $b and $c and $d and $e

}

rule malwaa
{
	meta:
		author = "leleo e theo"
		description = "Dtetectar por strings"
		date = "15/09"
	strings:
		$a = "bcdedit"
		$b = "set"
		$c = "default"
                $d = "recoveryenabled"
		$e = "no"


	condition:
		$a and $b and $c and $d and $e

}

rule mal
{
	meta:
		author = "leleo e theo"
		description = "Dtetectar por strings"
		date = "15/09"
	strings:
		$a = "bcdedit"
		$b = "set"
		$c = "default"
            $d = "bootstatuspolicy"
		$e = "default"


	condition:
		$a and $b and $c and $d and $e

}

