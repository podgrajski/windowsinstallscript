Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

# GUI Specs
Write-Host "Preverjam ce je  winget namescen..."

Try{
	# Check if winget is already installed
	$er = (invoke-expression "winget -v") 2>&1
	if ($lastexitcode) {throw $er}
	Write-Host "winget je namescen."
}
Catch{
	# winget is not installed. Install it from the Github release
	Write-Host "winget ni namescen, zacenjam namestitev!"
	
	$download = "https://github.com/microsoft/winget-cli/releases/download/v1.0.11692/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
	$output = $PSScriptRoot + "\winget-latest.appxbundle"
	Write-Host "Dowloading latest release"
	Invoke-WebRequest -Uri $download -OutFile $output
	
	Write-Host "Installing the package"
	Add-AppxPackage -Path $output
}
Finally {
	# Start installing the packages with winget
	#Get-Content .\winget.txt | ForEach-Object {
	#	iex ("winget install -e " + $_)
	#}
}

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = New-Object System.Drawing.Point(1050,700)
$Form.text                       = "App installer by PodGrajski"
$Form.StartPosition              = "CenterScreen"
$Form.TopMost                    = $false
$Form.BackColor                  = [System.Drawing.ColorTranslator]::FromHtml("#b8b8b8")
$Form.AutoScaleDimensions     = '192, 192'
$Form.AutoScaleMode           = "Dpi"
$Form.AutoSize                = $True
$Form.ClientSize              = '1050, 700'
$Form.FormBorderStyle         = 'FixedSingle'

# GUI Icon
$iconBytes                       = [Convert]::FromBase64String($iconBase64)
$stream                          = New-Object IO.MemoryStream($iconBytes, 0, $iconBytes.Length)
$stream.Write($iconBytes, 0, $iconBytes.Length)
$Form.Icon                    = [System.Drawing.Icon]::FromHandle((New-Object System.Drawing.Bitmap -Argument $stream).GetHIcon())

$Form.Width                   = $objImage.Width
$Form.Height                  = $objImage.Height

$Panel1                          = New-Object system.Windows.Forms.Panel
$Panel1.height                   = 639
$Panel1.width                    = 219
$Panel1.location                 = New-Object System.Drawing.Point(6,54)

$brave                           = New-Object system.Windows.Forms.Button
$brave.text                      = "Brave Browser test"
$brave.width                     = 212
$brave.height                    = 30
$brave.location                  = New-Object System.Drawing.Point(3,94)
$brave.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$firefox                         = New-Object system.Windows.Forms.Button
$firefox.text                    = "Firefox"
$firefox.width                   = 212
$firefox.height                  = 30
$firefox.location                = New-Object System.Drawing.Point(4,127)
$firefox.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$7zip                            = New-Object system.Windows.Forms.Button
$7zip.text                       = "7-Zip"
$7zip.width                      = 211
$7zip.height                     = 30
$7zip.location                   = New-Object System.Drawing.Point(4,363)
$7zip.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$irfanview                       = New-Object system.Windows.Forms.Button
$irfanview.text                  = "Irfanview (Image Viewer)"
$irfanview.width                 = 212
$irfanview.height                = 30
$irfanview.location              = New-Object System.Drawing.Point(3,195)
$irfanview.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$adobereader                     = New-Object system.Windows.Forms.Button
$adobereader.text                = "Adobe Reader DC"
$adobereader.width               = 212
$adobereader.height              = 30
$adobereader.location            = New-Object System.Drawing.Point(4,528)
$adobereader.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$notepad                         = New-Object system.Windows.Forms.Button
$notepad.text                    = "Notepad++"
$notepad.width                   = 212
$notepad.height                  = 30
$notepad.location                = New-Object System.Drawing.Point(4,461)
$notepad.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$gchrome                         = New-Object system.Windows.Forms.Button
$gchrome.text                    = "Google Chrome"
$gchrome.width                   = 212
$gchrome.height                  = 30
$gchrome.location                = New-Object System.Drawing.Point(4,161)
$gchrome.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$mpc                             = New-Object system.Windows.Forms.Button
$mpc.text                        = "Media Player Classic"
$mpc.width                       = 211
$mpc.height                      = 30
$mpc.location                    = New-Object System.Drawing.Point(4,329)
$mpc.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$vlc                             = New-Object system.Windows.Forms.Button
$vlc.text                        = "VLC"
$vlc.width                       = 212
$vlc.height                      = 30
$vlc.location                    = New-Object System.Drawing.Point(4,296)
$vlc.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$powertoys                       = New-Object system.Windows.Forms.Button
$powertoys.text                  = "PowerToys"
$powertoys.width                 = 211
$powertoys.height                = 30
$powertoys.location              = New-Object System.Drawing.Point(4,60)
$powertoys.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$winterminal                     = New-Object system.Windows.Forms.Button
$winterminal.text                = "Windows Terminal"
$winterminal.width               = 211
$winterminal.height              = 30
$winterminal.location            = New-Object System.Drawing.Point(4,26)
$winterminal.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$vscode                          = New-Object system.Windows.Forms.Button
$vscode.text                     = "VS Code"
$vscode.width                    = 211
$vscode.height                   = 30
$vscode.location                 = New-Object System.Drawing.Point(4,396)
$vscode.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Namestis lahko katerokoli od spodnjih aplikacij"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(26,5)
$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Panel2                          = New-Object system.Windows.Forms.Panel
$Panel2.height                   = 386
$Panel2.width                    = 211
$Panel2.location                 = New-Object System.Drawing.Point(239,54)

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Aplikacije"
$Label1.AutoSize                 = $true
$Label1.width                    = 230
$Label1.height                   = 25
$Label1.location                 = New-Object System.Drawing.Point(76,11)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',24)

$Form.controls.AddRange(@($Panel1,$Panel2,$Label3,$Label15,$Panel4,$PictureBox1,$Label1,$Label4,$Panel3))

$brave.Add_Click({
    Write-Host "Installing Brave Browser"
    winget install BraveSoftware.BraveBrowser | Out-Host
    if($?) { Write-Host "Installed Brave Browser" }
})

$firefox.Add_Click({
    Write-Host "Installing Firefox"
    winget install Mozilla.Firefox | Out-Host
    if($?) { Write-Host "Installed Firefox" }
})

$gchrome.Add_Click({
    Write-Host "Installing Google Chrome"
    winget install Google.Chrome | Out-Host
    if($?) { Write-Host "Installed Google Chrome" }
})

$irfanview.Add_Click({
    Write-Host "Installing Irfanview (Image Viewer)"
    winget install IrfanSkiljan.IrfanView | Out-Host
    if($?) { Write-Host "Installed Irfanview (Image Viewer)" }
})
$imageglass.Add_Click({
    Write-Host "Installing Image Glass (Image Viewer)"
    winget install DuongDieuPhap.ImageGlass | Out-Host
    if($?) { Write-Host "Installed Image Glass (Image Viewer)" }
})
$honeyview.Add_Click({
    Write-Host "Installing Bandisoft Honeyview (Image Viewer)"
    winget install Bandisoft.Honeyview | Out-Host
    if($?) { Write-Host "Installed Honeyview (Image Viewer)" }
})

$adobereader.Add_Click({
    Write-Host "Installing Adobe Reader DC"
    winget install Adobe.AdobeAcrobatReaderDC | Out-Host
    if($?) { Write-Host "Installed Adobe Reader DC" }
})

$notepad.Add_Click({
    Write-Host "Installing Notepad++"
    winget install Notepad++.Notepad++ | Out-Host
    if($?) { Write-Host "Installed Notepad++" }
})

$vlc.Add_Click({
    Write-Host "Installing VLC Media Player"
    winget install VideoLAN.VLC | Out-Host
    if($?) { Write-Host "Installed VLC Media Player" }
})

$mpc.Add_Click({
    Write-Host "Installing Media Player Classic"
    winget install clsid2.mpc-hc | Out-Host
    if($?) { Write-Host "Installed Media Player Classic" }
})

$7zip.Add_Click({
    Write-Host "Installing 7-Zip Compression Tool"
    winget install 7zip.7zip | Out-Host
    if($?) { Write-Host "Installed 7-Zip Compression Tool" }
})

$vscode.Add_Click({
    Write-Host "Installing Visual Studio Code"
    winget install Microsoft.VisualStudioCode | Out-Host
    if($?) { Write-Host "Installed Visual Studio Code" }
})

$vscodium.Add_Click({
    Write-Host "Installing VS Codium"
    winget install VSCodium.VSCodium | Out-Host
    if($?) { Write-Host "Installed VS Codium" }
})

$winterminal.Add_Click({
    Write-Host "Installing New Windows Terminal"
    winget install Microsoft.WindowsTerminal | Out-Host
    if($?) { Write-Host "Installed New Windows Terminal" }
})

$powertoys.Add_Click({
    Write-Host "Installing Microsoft PowerToys"
    winget install Microsoft.PowerToys | Out-Host
    if($?) { Write-Host "Installed Microsoft PowerToys" }
})

$everythingsearch.Add_Click({
    Write-Host "Installing Voidtools Everything Search"
    winget install voidtools.Everything | Out-Host
    if($?) { Write-Host "Installed Everything Search" }
})

$sumatrapdf.Add_Click({
    Write-Host "Installing Sumatra PDF"
    winget install SumatraPDF.SumatraPDF | Out-Host
    if($?) { Write-Host "Installed Sumatra PDF" }
})

$openshell.Add_Click({
    Write-Host "Installing OpenShell (Old Windows menu)"
    winget install openshellmenu | Out-Host
    Write-Host "Installed OpenShell"
})

[void]$Form.ShowDialog()
