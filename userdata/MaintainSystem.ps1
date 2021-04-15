<#
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
#>

function Write-Log {
  param (
    [string] $message,
    [string] $severity = 'INFO',
    [string] $source = 'MaintainSystem',
    [string] $logName = 'Application'
  )
  if (!([Diagnostics.EventLog]::Exists($logName)) -or !([Diagnostics.EventLog]::SourceExists($source))) {
    New-EventLog -LogName $logName -Source $source
  }
  switch ($severity) {
    'DEBUG' {
      $entryType = 'SuccessAudit'
      $eventId = 2
      break
    }
    'WARN' {
      $entryType = 'Warning'
      $eventId = 3
      break
    }
    'ERROR' {
      $entryType = 'Error'
      $eventId = 4
      break
    }
    default {
      $entryType = 'Information'
      $eventId = 1
      break
    }
  }
  Write-EventLog -LogName $logName -Source $source -EntryType $entryType -Category 0 -EventID $eventId -Message $message
  if ([Environment]::UserInteractive) {
    $fc = @{ 'Information' = 'White'; 'Error' = 'Red'; 'Warning' = 'DarkYellow'; 'SuccessAudit' = 'DarkGray' }[$entryType]
    Write-Host -object $message -ForegroundColor $fc
  }
}
function Run-MaintainSystem {
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    Get-SysprepState
    Remove-OldTaskDirectories
    Set-TaskFirewallExceptions
    Disable-DesiredStateConfig
    Invoke-OccReset

    $fingerprint = (Get-GpgKeyFingerprint)
    $gpgPublicKeyPath = ('{0}\Mozilla\OpenCloudConfig\occ-public.key' -f $env:ProgramData)
    if (-not ($fingerprint)) {
      New-GpgKey -gpgPublicKeyPath $gpgPublicKeyPath
    } else {
      if (Test-Path -Path $gpgPublicKeyPath -ErrorAction SilentlyContinue) {
        Write-Log -message ('{0} :: {1}' -f $($MyInvocation.MyCommand.Name), (Get-Content -Path $gpgPublicKeyPath -Raw)) -severity 'DEBUG'
      } else {
        Write-Log -message ('{0} :: error: {1} not found' -f $($MyInvocation.MyCommand.Name), $gpgPublicKeyPath) -severity 'ERROR'
      }
    }
    if (-not (Confirm-GenericWorkerConfig)) {
      Get-GenericWorkerConfig
    }
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Get-GpgKeyFingerprint {
  param (
    [string] $id = ('{0}@{1}' -f $env:USERNAME, [System.Net.Dns]::GetHostName()),
    [string] $gpgExePath = ('{0}\GNU\GnuPG\pub\gpg.exe' -f $(if ("${env:ProgramFiles(x86)}") { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles }))
  )
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    if (Test-Path -Path $gpgExePath -ErrorAction SilentlyContinue) {
      try {
        $fingerprint = @(($(& $gpgExePath @('--fingerprint', $id)) | ? { $_.Contains('Key fingerprint') }) | % { $_.Split('=')[1].Replace(' ', '')  })[0]
        if ([string]::IsNullOrWhitespace($fingerprint)) {
          $fingerprint = $null
          Write-Log -message ('{0} :: failed to determine fingerprint for id: {1}' -f $($MyInvocation.MyCommand.Name), $id) -severity 'WARN'
        } else {
          Write-Log -message ('{0} :: fingerprint: {1} determined for id: {2}' -f $($MyInvocation.MyCommand.Name), $fingerprint, $id) -severity 'INFO'
        }
      } catch {
        $fingerprint = $null
        Write-Log -message ('{0} :: failed to determine fingerprint for id: {1}. {2}' -f $($MyInvocation.MyCommand.Name), $id, $_.Exception.Message) -severity 'ERROR'
      }
    } else {
      $fingerprint = $null
      Write-Log -message ('{0} :: failed to determine fingerprint for id: {1}. {2} not found' -f $($MyInvocation.MyCommand.Name), $id, $gpgExePath) -severity 'WARN'
    }
    return $fingerprint
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function New-GpgKey {
  param (
    [string] $id = ('{0}@{1}' -f $env:USERNAME, [System.Net.Dns]::GetHostName()),
    [string] $gpgExePath = ('{0}\GNU\GnuPG\pub\gpg.exe' -f $(if ("${env:ProgramFiles(x86)}") { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles })),
    [string] $gpgKeyGenConfigPath = ('{0}\Mozilla\OpenCloudConfig\gpg-keygen-config.txt' -f $env:ProgramData),
    [string] $gpgPublicKeyPath = ('{0}\Mozilla\OpenCloudConfig\occ-public.key' -f $env:ProgramData),
    [string] $gpgBatchGenerateKeyStdOutPath = ('{0}\log\{1}.gpg-batch-generate-key.stdout.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss")),
    [string] $gpgBatchGenerateKeyStdErrPath = ('{0}\log\{1}.gpg-batch-generate-key.stderr.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss"))
  )
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    if (Test-Path -Path $gpgExePath -ErrorAction SilentlyContinue) {
      if (-not (Test-Path -Path $gpgPublicKeyPath -ErrorAction SilentlyContinue)) {
        try {
          New-Item -Path ([System.IO.Path]::GetDirectoryName($gpgKeyGenConfigPath)) -ItemType Directory -ErrorAction SilentlyContinue
          [IO.File]::WriteAllLines($gpgKeyGenConfigPath, @(
            'Key-Type: RSA',
            'Key-Length: 4096',
            'Subkey-Type: RSA',
            'Subkey-Length: 4096',
            'Expire-Date: 0',
            ('Name-Real: {0} {1}' -f $env:USERNAME, [System.Net.Dns]::GetHostName()),
            ('Name-Email: {0}@{1}' -f $env:USERNAME, [System.Net.Dns]::GetHostName()),
            '%no-protection',
            '%commit',
            '%echo done'
          ), (New-Object -TypeName 'System.Text.UTF8Encoding' -ArgumentList $false))
          if (Test-Path -Path $gpgKeyGenConfigPath -ErrorAction SilentlyContinue) {
            Write-Log -message ('{0} :: {1} created' -f $($MyInvocation.MyCommand.Name), $gpgKeyGenConfigPath) -severity 'DEBUG'
            Write-Log -message ('{0} :: {1}' -f $($MyInvocation.MyCommand.Name), (Get-Content -Path $gpgKeyGenConfigPath -Raw)) -severity 'DEBUG'
            Start-Process $gpgExePath -ArgumentList @('--batch', '--gen-key', $gpgKeyGenConfigPath) -Wait -NoNewWindow -PassThru -RedirectStandardOutput $gpgBatchGenerateKeyStdOutPath -RedirectStandardError $gpgBatchGenerateKeyStdErrPath
            if ((Get-Item -Path $gpgBatchGenerateKeyStdErrPath).Length -gt 0kb) {
              Write-Log -message ('{0} :: gpg --gen-key stderr: {1}' -f $($MyInvocation.MyCommand.Name), (Get-Content -Path $gpgBatchGenerateKeyStdErrPath -Raw)) -severity 'ERROR'
            }
            if ((Get-Item -Path $gpgBatchGenerateKeyStdOutPath).Length -gt 0kb) {
              Write-Log -message ('{0} :: gpg --gen-key stdout: {1}' -f $($MyInvocation.MyCommand.Name), (Get-Content -Path $gpgBatchGenerateKeyStdOutPath -Raw)) -severity 'INFO'
            }
            $fingerprint = (Get-GpgKeyFingerprint -id $id -gpgExePath $gpgExePath)
            if ($fingerprint) {
              & $gpgExePath @('--batch', '--export', '--output', $gpgPublicKeyPath, '--armor', $fingerprint)
              if (Test-Path -Path $gpgPublicKeyPath -ErrorAction SilentlyContinue) {
                Write-Log -message ('{0} :: {1}' -f $($MyInvocation.MyCommand.Name), (Get-Content -Path $gpgPublicKeyPath -Raw)) -severity 'DEBUG'
              } else {
                Write-Log -message ('{0} :: error: {1} not created' -f $($MyInvocation.MyCommand.Name), $gpgPublicKeyPath) -severity 'ERROR'
              }
            }
          } else {
            Write-Log -message ('{0} :: error: {1} not created' -f $($MyInvocation.MyCommand.Name), $gpgKeyGenConfigPath) -severity 'ERROR'
          }
        } catch {
          Write-Log -message ('{0} :: failed to create gpg key for id: {1}. {2}' -f $($MyInvocation.MyCommand.Name), $id, $_.Exception.Message) -severity 'ERROR'
        }
      } else {
        Write-Log -message ('{0} :: gpg public key detected at {1}' -f $($MyInvocation.MyCommand.Name), $gpgPublicKeyPath) -severity 'INFO'
      }
    } else {
      Write-Log -message ('{0} :: failed to create gpg key for id: {1}. {2} not found' -f $($MyInvocation.MyCommand.Name), $id, $gpgExePath) -severity 'WARN'
    }
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Confirm-GenericWorkerConfig {
  param (
    [string] $locationType = $(
      if (Get-Service -Name @('Ec2Config', 'AmazonSSMAgent') -ErrorAction 'SilentlyContinue') {
        'AWS'
      } elseif ((Get-Service -Name 'GCEAgent' -ErrorAction 'SilentlyContinue') -or (Test-Path -Path ('{0}\GooGet\googet.exe' -f $env:ProgramData) -ErrorAction 'SilentlyContinue')) {
        'GCP'
      } elseif (Get-Service -Name @('WindowsAzureGuestAgent', 'WindowsAzureNetAgentSvc') -ErrorAction 'SilentlyContinue') {
        'Azure'
      } else {
        try {
          # on azure we may trigger occ before the agent is installed or we may not have installed the agent (32 bit systems). this is a quick check to verify if that is what's happening here.
          if ((Invoke-WebRequest -Headers @{'Metadata'=$true} -UseBasicParsing -Uri ('http://169.254.169.254/metadata/instance?api-version={0}' -f '2019-06-04')).Content) {
            'Azure'
          }
        } catch {
          'DataCenter'
        }
      }
    ),
    [string] $workerType = $(
      switch ($locationType) {
        'AWS' {
          $(if ($publicKeys.StartsWith('0=mozilla-taskcluster-worker-')) { $publicKeys.Replace('0=mozilla-taskcluster-worker-', '') } else { (Invoke-WebRequest -Uri 'http://169.254.169.254/latest/user-data' -UseBasicParsing | ConvertFrom-Json).workerType })
        }
        'GCP' {
          (Invoke-WebRequest -Uri 'http://169.254.169.254/computeMetadata/v1beta1/instance/attributes/taskcluster' -UseBasicParsing | ConvertFrom-Json).workerConfig.openCloudConfig.workerType
        }
        'Azure' {
          (@(((Invoke-WebRequest -Headers @{'Metadata'=$true} -UseBasicParsing -Uri ('http://169.254.169.254/metadata/instance?api-version={0}' -f '2019-06-04')).Content) | ConvertFrom-Json).compute.tagsList | ? { $_.name -eq 'workerType' })[0].value
        }
        default {
          $null
        }
      }
    ),
    [string] $path = $(if (${env:PROCESSOR_ARCHITEW6432} -eq 'ARM64') { 'C:\generic-worker\gw.config' } else { 'C:\generic-worker\generic-worker.config' }),
    [hashtable] $equal = @{
      'rootUrl' = 'https://firefox-ci-tc.services.mozilla.com';
      'workerType' = $workerType;
      'wstAudience' = 'firefoxcitc';
      'clientId' = $(if (${env:PROCESSOR_ARCHITEW6432} -eq 'ARM64') { 'project/releng/generic-worker/bitbar-gecko-t-win10-aarch64' } else { ('project/releng/generic-worker/azure-{0}' -f $workerType.Replace('-az', '')) })
    },
    [hashtable] $in = @{
      'publicIP' = @(Get-NetIPConfiguration | ? { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne 'Disconnected' } | % { $_.IPv4Address.IPAddress })
    }
  )
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    $gwConfig=(Get-Content -Raw -Path $path | ConvertFrom-Json)
    if ((@($equal.Keys | ? { ($equal[$_] -ne $gwConfig."$_") }).Length -gt 0) -or (@($in.Keys | ? { (-not $in[$_].Contains($gwConfig."$_")) }).Length -gt 0)) {
      Write-Log -message ('{0} :: invalid config detected at {1}' -f $($MyInvocation.MyCommand.Name), $path) -severity 'INFO'
      foreach ($key in $equal.Keys) {
        Write-Log -message ('{0} :: {1} {2}: {3}' -f $($MyInvocation.MyCommand.Name), $(if ($equal[$_] -ne $gwConfig."$_") { 'invalid' } else { 'valid' }), $key, $gwConfig."$key") -severity 'INFO'
      }
      foreach ($key in $in.Keys) {
        Write-Log -message ('{0} :: {1} {2}: {3}' -f $($MyInvocation.MyCommand.Name), $(if (-not $in[$_].Contains($gwConfig."$_")) { 'invalid' } else { 'valid' }), $key, $gwConfig."$key") -severity 'INFO'
      }
      return $false
    }
    foreach ($key in $equal.Keys) {
      Write-Log -message ('{0} :: {1} {2}: {3}' -f $($MyInvocation.MyCommand.Name), $(if ($equal[$_] -ne $gwConfig."$_") { 'invalid' } else { 'valid' }), $key, $gwConfig."$key") -severity 'DEBUG'
    }
    foreach ($key in $in.Keys) {
      Write-Log -message ('{0} :: {1} {2}: {3}' -f $($MyInvocation.MyCommand.Name), $(if (-not $in[$_].Contains($gwConfig."$_")) { 'invalid' } else { 'valid' }), $key, $gwConfig."$key") -severity 'DEBUG'
    }
    return $true
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Get-GenericWorkerConfig {
  param (
    [string] $path = $(if (${env:PROCESSOR_ARCHITEW6432} -eq 'ARM64') { 'C:\generic-worker\gw.config' } else { 'C:\generic-worker\generic-worker.config' }),
    [string] $gpgExePath = ('{0}\GNU\GnuPG\pub\gpg.exe' -f $(if ("${env:ProgramFiles(x86)}") { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles })),
    [string] $sourceOrg = $(if ((Test-Path -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -ErrorAction SilentlyContinue) -and (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Organisation' -ErrorAction SilentlyContinue)) { (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Organisation').Organisation } else { 'mozilla-releng' }),
    [string] $sourceRepo = $(if ((Test-Path -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -ErrorAction SilentlyContinue) -and (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Repository' -ErrorAction SilentlyContinue)) { (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Repository').Repository } else { 'OpenCloudConfig' }),
    [string] $sourceRev = $(if ((Test-Path -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -ErrorAction SilentlyContinue) -and (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Revision' -ErrorAction SilentlyContinue)) { (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Revision').Revision } else { 'master' })
  )
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    if (Test-Path -Path ('{0}.gpg' -f $path) -ErrorAction SilentlyContinue) {
      Remove-Item -Path ('{0}.gpg' -f $path) -Force -ErrorAction SilentlyContinue
      Write-Log -message ('{0} :: deleted: {1}' -f $($MyInvocation.MyCommand.Name), ('{0}.gpg' -f $path)) -severity 'DEBUG'
    }
    try {
      $url = ('https://github.com/{0}/{1}/raw/{2}/cfg/generic-worker/{3}.json.gpg' -f $sourceOrg, $sourceRepo, $sourceRev, $(if ([System.Net.Dns]::GetHostName().ToLower().StartsWith('yoga-')) { 't-lenovoyogac630-{0}' -f [System.Net.Dns]::GetHostName().Split('-')[1] } else { [System.Net.Dns]::GetHostName().ToLower() }))
      (New-Object Net.WebClient).DownloadFile($url, ('{0}.gpg' -f $path))
      Write-Log -message ('{0} :: downloaded: {1}' -f $($MyInvocation.MyCommand.Name), ('{0}.gpg' -f $path)) -severity 'DEBUG'
      try {
        if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
          Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
          Write-Log -message ('{0} :: deleted: {1}' -f $($MyInvocation.MyCommand.Name), $path) -severity 'DEBUG'
        }
        Start-Process $gpgExePath -ArgumentList @('-d', ('{0}.gpg' -f $path)) -Wait -NoNewWindow -PassThru -RedirectStandardOutput $path -RedirectStandardError ('{0}\log\{1}.gpg-decrypt-{2}.stderr.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss"), [IO.Path]::GetFileNameWithoutExtension($path))
        if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
          Write-Log -message ('{0} :: decrypted {1} to {2}' -f $($MyInvocation.MyCommand.Name), ('{0}.gpg' -f $path), $path) -severity 'INFO'
        }
        Remove-Item -Path ('{0}.gpg' -f $path) -Force -ErrorAction SilentlyContinue
        Write-Log -message ('{0} :: deleted {1}' -f $($MyInvocation.MyCommand.Name), ('{0}.gpg' -f $path))
      } catch {
        Write-Log -message ('{0} :: decryption of {1} to {2} failed. {3}' -f $($MyInvocation.MyCommand.Name), ('{0}.gpg' -f $path), $path, $_.Exception.Message) -severity 'ERROR'
      }
    } catch {
      Write-Log -message ('{0} :: download of {1} to {2} failed. {3}' -f $($MyInvocation.MyCommand.Name), $url, ('{0}.gpg' -f $path), $_.Exception.Message) -severity 'ERROR'
    }
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Remove-OldTaskDirectories {
  param (
    [string[]] $targets = @('Z:\task_*', 'C:\Users\task_*', 'C:\tasks\task_*')
  )
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    foreach ($target in ($targets | ? { (Test-Path -Path ('{0}:\' -f $_[0]) -ErrorAction SilentlyContinue) })) {
      $all_task_paths = @(Get-ChildItem -Path $target | Sort-Object -Property { $_.CreationTime })
      # https://bugzil.la/1543490
      # Retain the _two_ most recently created task folders, since one is for
      # the currently running task, and one is already prepared for the
      # subsequent task after the next reboot.
      if ($all_task_paths.length -gt 2) {
        Write-Log -message ('{0} :: {1} task directories detected matching pattern: {2}' -f $($MyInvocation.MyCommand.Name), $all_task_paths.length, $target) -severity 'INFO'
        # Note, arrays are zero-based, so the last entry for deletion when
        # keeping two folders is actually $all_task_paths.Length-3.
        $old_task_paths = $all_task_paths[0..($all_task_paths.Length-3)]
        foreach ($old_task_path in $old_task_paths) {
          try {
            & takeown.exe @('/a', '/f', $old_task_path, '/r', '/d', 'Y')
            & icacls.exe @($old_task_path, '/grant', 'Administrators:F', '/t')
            Remove-Item -Path $old_task_path -Force -Recurse
            Write-Log -message ('{0} :: removed task directory: {1}, with last write time: {2}' -f $($MyInvocation.MyCommand.Name), $old_task_path.FullName, $old_task_path.LastWriteTime) -severity 'INFO'
          } catch {
            Write-Log -message ('{0} :: failed to remove task directory: {1}, with last write time: {2}. {3}' -f $($MyInvocation.MyCommand.Name), $old_task_path.FullName, $old_task_path.LastWriteTime, $_.Exception.Message) -severity 'ERROR'
          }
        }
      } elseif ($all_task_paths.length -eq 1) {
        Write-Log -message ('{0} :: a single task directory was detected at: {1}, with last write time: {2}' -f $($MyInvocation.MyCommand.Name), $all_task_paths[0].FullName, $all_task_paths[0].LastWriteTime) -severity 'DEBUG'
      } else {
        Write-Log -message ('{0} :: no task directories detected matching pattern: {1}' -f$($MyInvocation.MyCommand.Name), $target) -severity 'DEBUG'
      }
    }
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Set-TaskFirewallExceptions {
  param (
    [string] $target = $(if (Test-Path -Path 'Z:\' -ErrorAction SilentlyContinue) { 'Z:\task_*' } else { 'C:\Users\task_*' }),
    [hashtable] $childPaths = @{
      'ssltunnel' = 'build\tests\bin\ssltunnel.exe';
      'python' = 'build\venv\scripts\python.exe'
    }
  )
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    $all_task_paths = @(Get-ChildItem -Path $target | Sort-Object -Property { $_.LastWriteTime } -Descending)
    if ($all_task_paths.Length) {
      foreach ($task_path in $all_task_paths) {
        foreach ($key in $childPaths.Keys) {
          $childPath = $childPaths.Item($key)
          $program = (Join-Path -Path $task_path -ChildPath $childPath)
          foreach ($direction in @('in', 'out')) {
            $ruleName = ('generic-worker-{0}-{1}-{2}' -f (Get-Item -Path $task_path).Basename, $key, $direction)
            try {
              if ((Get-Command 'Get-NetFirewallRule' -ErrorAction 'SilentlyContinue') -and (Get-Command 'Set-NetFirewallRule' -ErrorAction 'SilentlyContinue') -and (Get-Command 'New-NetFirewallRule' -ErrorAction 'SilentlyContinue')) {
                if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction 'SilentlyContinue') {
                  Set-NetFirewallRule -DisplayName $ruleName -Program $program
                  Write-Log -message ('{0} :: firewall rule: {1} updated with program: {2}' -f $($MyInvocation.MyCommand.Name), $ruleName, $program) -severity 'DEBUG'
                } else {
                  New-NetFirewallRule -DisplayName $ruleName -Program $program -Direction ('{0}bound' -f $direction) -Action Allow
                  Write-Log -message ('{0} :: firewall rule: {1} created with program: {2}' -f $($MyInvocation.MyCommand.Name), $ruleName, $program) -severity 'INFO'
                }
              } else {
                if ((& 'netsh.exe' @('advfirewall', 'firewall', 'show', 'rule', ('name={0}' -f $ruleName)))[1] -ne 'No rules match the specified criteria.') {
                  & 'netsh.exe' @('advfirewall', 'firewall', 'set', 'rule', ('name={0}' -f $ruleName), ('program={0}' -f $program))
                  Write-Log -message ('{0} :: firewall rule: {1} updated with program: {2}' -f $($MyInvocation.MyCommand.Name), $ruleName, $program) -severity 'DEBUG'
                } else {
                  & 'netsh.exe' @('advfirewall', 'firewall', 'add', 'rule', ('name={0}' -f $ruleName), ('program={0}' -f $program), ('dir={0}' -f $direction), 'action=allow')
                  Write-Log -message ('{0} :: firewall rule: {1} created with program: {2}' -f $($MyInvocation.MyCommand.Name), $ruleName, $program) -severity 'INFO'
                }
              }
            } catch {
              Write-Log -message ('{0} :: error setting firewall rule: {1}. {2}' -f $($MyInvocation.MyCommand.Name), $ruleName, $_.Exception.Message) -severity 'ERROR'
            }
          }
        }
      }
    } else {
      Write-Log -message ('{0} :: no task directories detected matching pattern: {1}' -f$($MyInvocation.MyCommand.Name), $target) -severity 'DEBUG'
    }
    # remove old firewall rules for completed tasks
    $gwFirewallRuleNamePattern = 'generic-worker-task_*'
    # $allTaskFirewallExceptions = (Get-NetFirewallRule -DisplayName $gwFirewallRuleNamePattern)
    $allTaskFirewallExceptions = ((New-object -ComObject HNetCfg.FwPolicy2).Rules | ? { $_.Name -like $gwFirewallRuleNamePattern })
    foreach ($taskFirewallException in $allTaskFirewallExceptions) {
      # $ruleName = $taskFirewallException.DisplayName
      $ruleName = $taskFirewallException.Name
      $taskName = [regex]::Match($ruleName, '^generic-worker-(task_\d*)-.*$').Groups[1].Value
      if ((Test-Path -Path ('Z:\{0}' -f $taskName) -ErrorAction SilentlyContinue) -or (Test-Path -Path ('C:\Users\{0}' -f $taskName) -ErrorAction SilentlyContinue)) {
        Write-Log -message ('{0} :: skipping removal of firewall rule: {1} which corresponds to active or scheduled task' -f $($MyInvocation.MyCommand.Name), $ruleName) -severity 'DEBUG'
      } else {
        try {
          if (Get-Command 'Remove-NetFirewallRule' -ErrorAction 'SilentlyContinue') {
            Remove-NetFirewallRule -DisplayName $ruleName
          } else {
            & 'netsh.exe' @('advfirewall', 'firewall', 'delete', 'rule', ('name={0}' -f $ruleName))
          }
          Write-Log -message ('{0} :: expired firewall rule: {1} removed' -f $($MyInvocation.MyCommand.Name), $ruleName) -severity 'INFO'
        } catch {
          Write-Log -message ('{0} :: error removing expired firewall rule: {1}. {2}' -f $($MyInvocation.MyCommand.Name), $ruleName, $_.Exception.Message) -severity 'ERROR'
        }
      }
    }
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Invoke-OccReset {
  param (
    [string] $sourceOrg = $(if ((Test-Path -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -ErrorAction SilentlyContinue) -and (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Organisation' -ErrorAction SilentlyContinue)) { (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Organisation').Organisation } else { 'mozilla-releng' }),
    [string] $sourceRepo = $(if ((Test-Path -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -ErrorAction SilentlyContinue) -and (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Repository' -ErrorAction SilentlyContinue)) { (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Repository').Repository } else { 'OpenCloudConfig' }),
    [string] $sourceRev = $(if ((Test-Path -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -ErrorAction SilentlyContinue) -and (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Revision' -ErrorAction SilentlyContinue)) { (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Mozilla\OpenCloudConfig\Source' -Name 'Revision').Revision } else { 'master' })
  )
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    try {
      if (${env:COMPUTERNAME}.ToLower().StartsWith('t-w1064-') -or (${env:PROCESSOR_ARCHITEW6432} -eq 'ARM64')) {
        foreach ($script in @('rundsc', 'MaintainSystem')) {
          $guid = [Guid]::NewGuid()
          $scriptUrl = ('https://raw.githubusercontent.com/{0}/{1}/{2}/userdata/{3}.ps1?{4}' -f $sourceOrg, $sourceRepo, $sourceRev, $script, $guid)
          $newScriptPath = ('C:\dsc\{0}-{1}.ps1' -f $script, $guid)
          try {
            (New-Object Net.WebClient).DownloadFile($scriptUrl, $newScriptPath)
          } catch {
            Write-Log -message ('{0} :: error downloading {1} to {2}. {3}' -f $($MyInvocation.MyCommand.Name), $scriptUrl, $newScriptPath, $_.Exception.Message) -severity 'ERROR'
          }
          if (Test-Path -Path $newScriptPath -ErrorAction SilentlyContinue) {
            $oldScriptPath = ('C:\dsc\{0}.ps1' -f $script)
            if (Test-Path -Path $oldScriptPath -ErrorAction SilentlyContinue) {
              $newSha512Hash = (Get-FileHash -Path $newScriptPath -Algorithm 'SHA512').Hash
              $oldSha512Hash = (Get-FileHash -Path $oldScriptPath -Algorithm 'SHA512').Hash

              if ($newSha512Hash -ne $oldSha512Hash) {
                Write-Log -message ('{0} :: {1} hashes do not match (old: {2}, new: {3})' -f $($MyInvocation.MyCommand.Name), $script, ('{0}...{1}' -f $oldSha512Hash.Substring(0, 9), $oldSha512Hash.Substring($oldSha512Hash.length - 9, 9)), ('{0}...{1}' -f $newSha512Hash.Substring(0, 9), $newSha512Hash.Substring($newSha512Hash.length - 9, 9))) -severity 'INFO'
                Remove-Item -Path $oldScriptPath -force -ErrorAction SilentlyContinue
                Move-item -LiteralPath $newScriptPath -Destination $oldScriptPath
              } else {
                Write-Log -message ('{0} :: {1} hashes match (old: {2}, new: {3})' -f $($MyInvocation.MyCommand.Name), $script, ('{0}...{1}' -f $oldSha512Hash.Substring(0, 9), $oldSha512Hash.Substring($oldSha512Hash.length - 9, 9)), ('{0}...{1}' -f $newSha512Hash.Substring(0, 9), $newSha512Hash.Substring($newSha512Hash.length - 9, 9))) -severity 'DEBUG'
                Remove-Item -Path $newScriptPath -force -ErrorAction SilentlyContinue
              }
            } else {
              Move-item -LiteralPath $newScriptPath -Destination $oldScriptPath
              Write-Log -message ('{0} :: existing {1} not found. downloaded {1} applied' -f $($MyInvocation.MyCommand.Name), $script) -severity 'INFO'
            }
          } else {
            Write-Log -message ('{0} :: comparison skipped for {1}' -f $($MyInvocation.MyCommand.Name), $script) -severity 'INFO'
          }
        }
      }
      $remotePatches = @(
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/debug.ps1',
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/run-debug-commands.ps1',
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/set-source.ps1',
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/set-gw-master-config.ps1',
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/set-shared-key.ps1',
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/download-and-decrypt-resources.ps1',
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/debug-keys.ps1',
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/create-instance-key.ps1',
        'https://gist.githubusercontent.com/grenade/18b237e50919152a299d0082a396c1f8/raw/log-instance-public-key.ps1'
      )
      foreach ($remotePatch in $remotePatches) {
        try {
          Write-Log -message ('{0} :: executing remote patch {1}' -f $($MyInvocation.MyCommand.Name), $remotePatch) -severity 'DEBUG'
          Invoke-Expression (New-Object Net.WebClient).DownloadString(('{0}?{1}' -f $remotePatch, [Guid]::NewGuid()))
          Write-Log -message ('{0} :: remote patch executed {1}' -f $($MyInvocation.MyCommand.Name), $remotePatch) -severity 'DEBUG'
        } catch {
          Write-Log -message ('{0} :: error executing remote patch script {1}. {2}' -f $($MyInvocation.MyCommand.Name), $remotePatch, $_.Exception.Message) -severity 'ERROR'
          if ($_.Exception.InnerException) {
            Write-Log -message ('{0} :: inner exception: {1}' -f $($MyInvocation.MyCommand.Name), $_.Exception.InnerException.Message) -severity 'ERROR';
          }
        }
      }
      if ((${env:PROCESSOR_ARCHITEW6432} -eq 'ARM64') -and (-not (Test-ScheduledTaskExists -TaskName 'RunDesiredStateConfigurationAtStartup'))) {
        New-PowershellScheduledTask -taskName 'RunDesiredStateConfigurationAtStartup' -scriptUrl ('https://raw.githubusercontent.com/{0}/{1}/{2}/userdata/rundsc.ps1?{3}' -f $sourceOrg, $sourceRepo, $sourceRev, [Guid]::NewGuid()) -scriptPath 'C:\dsc\rundsc.ps1' -sc 'onstart'
      }
    } catch {
      Write-Log -message ('{0} :: exception - {1}' -f $($MyInvocation.MyCommand.Name), $_.Exception.Message) -severity 'ERROR'
    }
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Test-ScheduledTaskExists {
  param (
    [string] $taskName
  )
  if (Get-Command 'Get-ScheduledTask' -ErrorAction 'SilentlyContinue') {
    return [bool](Get-ScheduledTask -TaskName $taskName -ErrorAction 'SilentlyContinue')
  }
  # sceduled task commandlets are unavailable on windows 7, so we use com to access sceduled tasks here.
  $scheduleService = (New-Object -ComObject Schedule.Service)
  $scheduleService.Connect()
  return (@($scheduleService.GetFolder("\").GetTasks(0) | ? { $_.Name -eq $taskName }).Length -gt 0)
}
function New-PowershellScheduledTask {
  param (
    [string] $taskName,
    [string] $scriptUrl,
    [string] $scriptPath,
    [string] $sc,
    [string] $mo = $null
  )
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    # delete scheduled task if it pre-exists
    if ((Test-ScheduledTaskExists -TaskName $taskName)) {
      try {
        Start-Process 'schtasks.exe' -ArgumentList @('/delete', '/tn', $taskName, '/f') -Wait -NoNewWindow -PassThru -RedirectStandardOutput ('{0}\log\{1}.schtask-{2}-delete.stdout.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss"), $taskName) -RedirectStandardError ('{0}\log\{1}.schtask-{2}-delete.stderr.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss"), $taskName)
        Write-Log -message ('{0} :: scheduled task: {1} deleted.' -f $($MyInvocation.MyCommand.Name), $taskName) -severity 'INFO'
      }
      catch {
        Write-Log -message ('{0} :: failed to delete scheduled task: {1}. {2}' -f $($MyInvocation.MyCommand.Name), $taskName, $_.Exception.Message) -severity 'ERROR'
      }
    }
    # delete script if it pre-exists
    if (Test-Path -Path $scriptPath -ErrorAction SilentlyContinue) {
      Remove-Item -Path $scriptPath -confirm:$false -force
      Write-Log -message ('{0} :: {1} deleted.' -f $($MyInvocation.MyCommand.Name), $scriptPath) -severity 'INFO'
    }
    # download script
    try {
      (New-Object Net.WebClient).DownloadFile($scriptUrl, $scriptPath)
      Write-Log -message ('{0} :: {1} downloaded from {2}.' -f $($MyInvocation.MyCommand.Name), $scriptPath, $scriptUrl) -severity 'INFO'
    }
    catch {
      Write-Log -message ('{0} :: failed to download scheduled task script {1} from {2}. {3}' -f $($MyInvocation.MyCommand.Name), $scriptPath, $scriptUrl, $_.Exception.Message) -severity 'ERROR'
    }
    if (Test-Path -Path $scriptPath -ErrorAction SilentlyContinue) {
      # create scheduled task
      try {
        if ($mo) {
          Start-Process 'schtasks.exe' -ArgumentList @('/create', '/tn', $taskName, '/sc', $sc, '/mo', $mo, '/ru', 'SYSTEM', '/rl', 'HIGHEST', '/tr', ('"{0}\powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -File \"{1}\" -ExecutionPolicy RemoteSigned -ConsoleOutputFile \"{2}\" "' -f $pshome, $scriptPath, $scriptPath.Replace('.ps1', '-run.log')), '/f') -Wait -NoNewWindow -PassThru -RedirectStandardOutput ('{0}\log\{1}.schtask-{2}-create.stdout.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss"), $taskName) -RedirectStandardError ('{0}\log\{1}.schtask-{2}-create.stderr.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss"), $taskName)
        } else {
          Start-Process 'schtasks.exe' -ArgumentList @('/create', '/tn', $taskName, '/sc', $sc, '/ru', 'SYSTEM', '/rl', 'HIGHEST', '/tr', ('"{0}\powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -File \"{1}\" -ExecutionPolicy RemoteSigned -ConsoleOutputFile \"{2}\" "' -f $pshome, $scriptPath, $scriptPath.Replace('.ps1', '-run.log')), '/f') -Wait -NoNewWindow -PassThru -RedirectStandardOutput ('{0}\log\{1}.schtask-{2}-create.stdout.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss"), $taskName) -RedirectStandardError ('{0}\log\{1}.schtask-{2}-create.stderr.log' -f $env:SystemDrive, [DateTime]::Now.ToString("yyyyMMddHHmmss"), $taskName)
        }
        Write-Log -message ('{0} :: scheduled task: {1} created.' -f $($MyInvocation.MyCommand.Name), $taskName) -severity 'INFO'
      }
      catch {
        Write-Log -message ('{0} :: failed to create scheduled task: {1}. {2}' -f $($MyInvocation.MyCommand.Name), $taskName, $_.Exception.Message) -severity 'ERROR'
      }
    } else {
      Write-Log -message ('{0} :: skipped creation of scheduled task: {1}. missing script: {2}' -f $($MyInvocation.MyCommand.Name), $taskName, $scriptPath) -severity 'ERROR'
    }
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Disable-DesiredStateConfig {
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    try {
      if (${env:COMPUTERNAME}.ToLower().StartsWith('t-w1064-') -or ${env:COMPUTERNAME}.ToLower().StartsWith('yoga-')) {
        # terminate any running dsc process
        $dscpid = (Get-WmiObject msft_providers | ? {$_.provider -like 'dsccore'} | Select-Object -ExpandProperty HostProcessIdentifier)
        if ($dscpid) {
          Get-Process -Id $dscpid | Stop-Process -f
          Write-Log -message ('{0} :: dsc process with pid {1}, stopped.' -f $($MyInvocation.MyCommand.Name), $dscpid) -severity 'DEBUG'
        }
        foreach ($mof in @('Previous', 'backup', 'Current')) {
          if (Test-Path -Path ('{0}\System32\Configuration\{1}.mof' -f $env:SystemRoot, $mof) -ErrorAction SilentlyContinue) {
            Remove-Item -Path ('{0}\System32\Configuration\{1}.mof' -f $env:SystemRoot, $mof) -confirm:$false -force
            Write-Log -message ('{0}\System32\Configuration\{1}.mof deleted' -f $env:SystemRoot, $mof) -severity 'INFO'
          }
        }
      }
    }
    catch {
      Write-Log -message ('{0} :: failed to disable dsc: {1}' -f $($MyInvocation.MyCommand.Name), $_.Exception.Message) -severity 'ERROR'
    }
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
function Get-SysprepState {
  begin {
    Write-Log -message ('{0} :: begin - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
  process {
    try {
      $sysprepState = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State' -Name 'ImageState').ImageState
      Write-Log -message ('{0} :: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State ImageState read as {1}' -f $($MyInvocation.MyCommand.Name), $sysprepState) -severity 'DEBUG'
    } catch {
      Write-Log -message ('{0} :: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State ImageState read failure. {1}' -f $($MyInvocation.MyCommand.Name), $_.Exception.Message) -severity 'ERROR'
      $sysprepState = $null
    }
    return $sysprepState
  }
  end {
    Write-Log -message ('{0} :: end - {1:o}' -f $($MyInvocation.MyCommand.Name), (Get-Date).ToUniversalTime()) -severity 'DEBUG'
  }
}
Run-MaintainSystem
