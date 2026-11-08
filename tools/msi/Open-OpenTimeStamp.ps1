#Requires -Version 5.1

[CmdletBinding()]
param([switch]$Admin)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

try {
    $configuration = Get-ItemProperty -LiteralPath 'HKLM:\Software\OpenTimeStamp\Installer'
    $saved = $configuration.PSObject.Properties['Endpoints']
    $links = @(foreach ($entry in @(if ($saved) { $saved.Value })) {
        $parts = ([string]$entry).Split('|', 2)
        $url = $null
        if ($parts.Count -ne 2 -or -not [uri]::TryCreate($parts[1], [UriKind]::Absolute, [ref]$url) -or
            $url.Scheme -notin @('http', 'https') -or $url.UserInfo -or $url.Query -or $url.Fragment) {
            throw 'The saved endpoint list contains an invalid URL. Repair the installation.'
        }
        [pscustomobject]@{ Name = $parts[0]; Url = $url.AbsoluteUri; Scheme = $url.Scheme }
    })
    if ($links.Count -eq 0) { throw 'No endpoint URLs were saved by setup.' }
    if ($Admin) {
        $link = $links | Where-Object Name -eq 'Administration' |
            Sort-Object Scheme -Descending | Select-Object -First 1
        if (-not $link) { throw 'The saved endpoint list does not include administration.' }
        Start-Process -FilePath $link.Url
        return
    }

    $form = [Windows.Forms.Form]::new()
    $form.Text = 'OpenTimeStamp Setup Complete'
    $form.AutoScaleMode = [Windows.Forms.AutoScaleMode]::Dpi
    $form.ClientSize = [Drawing.Size]::new(740, 560)
    $form.MinimumSize = [Drawing.Size]::new(580, 430)
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    $form.Font = [Drawing.Font]::new('Segoe UI', 10)
    $form.BackColor = [Drawing.Color]::White
    $form.Icon = [Drawing.Icon]::new((Join-Path $PSScriptRoot 'OpenTimeStamp.ico'))

    $header = [Windows.Forms.Panel]::new()
    $header.Dock = [Windows.Forms.DockStyle]::Top
    $header.Height = 112
    $picture = [Windows.Forms.PictureBox]::new()
    $picture.Location = [Drawing.Point]::new(20, 20)
    $picture.Size = [Drawing.Size]::new(68, 68)
    $picture.SizeMode = [Windows.Forms.PictureBoxSizeMode]::Zoom
    $picture.Image = [Drawing.Image]::FromFile((Join-Path $PSScriptRoot 'OpenTimeStamp.png'))
    $title = [Windows.Forms.Label]::new()
    $title.Text = 'OpenTimeStamp Is Installed'
    $title.Font = [Drawing.Font]::new('Segoe UI', 17, [Drawing.FontStyle]::Bold)
    $title.ForeColor = [Drawing.ColorTranslator]::FromHtml('#0b5cab')
    $title.AutoSize = $true
    $title.Location = [Drawing.Point]::new(105, 18)
    $description = [Windows.Forms.Label]::new()
    $description.Text = "URLs for the selected IIS website are listed below.`r`nUse Administration on this server to configure signing."
    $description.AutoSize = $true
    $description.Location = [Drawing.Point]::new(108, 59)
    $header.Controls.AddRange(@($picture, $title, $description))

    $list = [Windows.Forms.FlowLayoutPanel]::new()
    $list.Dock = [Windows.Forms.DockStyle]::Fill
    $list.FlowDirection = [Windows.Forms.FlowDirection]::TopDown
    $list.WrapContents = $false
    $list.AutoScroll = $true
    $list.Padding = [Windows.Forms.Padding]::new(22, 0, 22, 12)
    foreach ($entry in $links) {
        $label = [Windows.Forms.Label]::new()
        $label.AutoSize = $true
        $label.Text = $entry.Name
        $label.Margin = [Windows.Forms.Padding]::new(0, 14, 0, 2)
        $label.Font = [Drawing.Font]::new($form.Font, [Drawing.FontStyle]::Bold)
        $link = [Windows.Forms.LinkLabel]::new()
        $link.AutoSize = $true
        $link.Text = $entry.Url
        $link.Tag = $entry.Url
        $link.Margin = [Windows.Forms.Padding]::new(0, 0, 0, 2)
        $link.LinkColor = [Drawing.ColorTranslator]::FromHtml('#0b5cab')
        $link.add_LinkClicked({
            param($sender, $eventArgs)
            try { Start-Process -FilePath ([string]$sender.Tag) }
            catch {
                [void][Windows.Forms.MessageBox]::Show('The browser could not open this URL.', 'OpenTimeStamp',
                    [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Error)
            }
        })
        $list.Controls.AddRange(@($label, $link))
    }
    $list.add_SizeChanged({
        param($sender, $eventArgs)
        $width = [Math]::Max(100, $sender.ClientSize.Width - 65)
        foreach ($control in $sender.Controls) { $control.MaximumSize = [Drawing.Size]::new($width, 0) }
    })

    $footer = [Windows.Forms.FlowLayoutPanel]::new()
    $footer.Dock = [Windows.Forms.DockStyle]::Bottom
    $footer.Height = 62
    $footer.Padding = [Windows.Forms.Padding]::new(16)
    $footer.FlowDirection = [Windows.Forms.FlowDirection]::RightToLeft
    $finish = [Windows.Forms.Button]::new()
    $finish.Text = '&Finish'
    $finish.Size = [Drawing.Size]::new(95, 30)
    $finish.DialogResult = [Windows.Forms.DialogResult]::OK
    $footer.Controls.Add($finish)
    $form.AcceptButton = $finish
    $form.CancelButton = $finish
    $form.Controls.AddRange(@($list, $footer, $header))
    try { [void]$form.ShowDialog() }
    finally { $picture.Image.Dispose(); $form.Icon.Dispose(); $form.Dispose() }
}
catch {
    [void][Windows.Forms.MessageBox]::Show($_.Exception.Message, 'OpenTimeStamp',
        [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Error)
}
