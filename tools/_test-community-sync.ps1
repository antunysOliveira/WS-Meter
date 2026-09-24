param([string]$mode = "unit")

$exe = Join-Path $PSScriptRoot "..\WS-engine.exe"

function Invoke-Ws {
    param([string[]]$Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = $Arguments -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $out = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    return @{ Out = $out; Exit = $proc.ExitCode }
}

if ($mode -eq "unit") {
    # Test 0a: --community-unit-loadmem (LoadLocalSnapshotFromMemJsons)
    $r0a = Invoke-Ws @('--community-unit-loadmem')
    if ($r0a.Exit -ne 0) { Write-Error "FAIL unit-loadmem: exit=$($r0a.Exit) out=$($r0a.Out)"; exit 1 }
    Write-Host $r0a.Out.Trim()

    # Test 0: --community-unit-delta (pure helpers)
    $r0 = Invoke-Ws @('--community-unit-delta')
    if ($r0.Exit -ne 0) { Write-Error "FAIL unit-delta: $($r0.Out)"; exit 1 }
    Write-Host $r0.Out.Trim()

    # (unit-cache removido — disk cache eliminado, backend virou fonte de verdade)

    # Test 1: --community-status roda sem crashear e produz output rico
    $r = Invoke-Ws @('--community-status')
    if ($r.Exit -ne 0) { Write-Error "FAIL: --community-status exit=$($r.Exit)"; exit 1 }
    $expected = @("client_id:", "enabled:", "backend:", "cache:", "last_pull_utc:")
    foreach ($needle in $expected) {
        if ($r.Out -notmatch [regex]::Escape($needle)) {
            Write-Error "FAIL: --community-status missing '$needle' (got: $($r.Out))"
            exit 1
        }
    }
    Write-Host "PASS: --community-status rich output"

    # Test 2: TryLookup(0) via CLI probe
    $r2 = Invoke-Ws @('--community-probe', '0')
    if ($r2.Out -notmatch "not found") { Write-Error "FAIL: TryLookup(0) should return false (got: $($r2.Out))"; exit 1 }
    Write-Host "PASS: TryLookup(0) returns false"

    # Test 3: me.txt setado → client_id = 0x<HEX>
    $root = Split-Path $exe -Parent
    $meBak = Join-Path $root "ws-engine.me.txt"
    $cidBak = Join-Path $root "ws-engine.client-id.txt"
    $meBackup = if (Test-Path $meBak) { Get-Content $meBak -Raw } else { $null }
    $cidBackup = if (Test-Path $cidBak) { Get-Content $cidBak -Raw } else { $null }

    try {
        Set-Content -Path $meBak -Value "6892962"  # 0x00692DA2 decimal
        if (Test-Path $cidBak) { Remove-Item $cidBak }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.Arguments = '--community-status'
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $out = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        if ($out -notmatch "client_id: 0x00692DA2") { Write-Error "FAIL: me.txt not honored ($out)"; exit 1 }
        Write-Host "PASS: me.txt → client_id"

        # Test 4: me.txt vazio + client-id.txt existe → usa client-id.txt
        Remove-Item $meBak
        Set-Content -Path $cidBak -Value "abc123def456"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.Arguments = '--community-status'
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $out = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        if ($out -notmatch "client_id: abc123def456") { Write-Error "FAIL: client-id.txt not honored"; exit 1 }
        Write-Host "PASS: client-id.txt fallback"

        # Test 5: nenhum arquivo → gera GUID + salva
        Remove-Item $cidBak
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.Arguments = '--community-status'
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $out = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        if ($out -notmatch "client_id: [a-f0-9]{12}") { Write-Error "FAIL: no GUID generated ($out)"; exit 1 }
        if (-not (Test-Path $cidBak)) { Write-Error "FAIL: client-id.txt not written"; exit 1 }
        Write-Host "PASS: GUID gen + persist"
    } finally {
        if ($meBackup) { Set-Content -Path $meBak -Value $meBackup } elseif (Test-Path $meBak) { Remove-Item $meBak }
        if ($cidBackup) { Set-Content -Path $cidBak -Value $cidBackup } elseif (Test-Path $cidBak) { Remove-Item $cidBak }
    }
}

if ($mode -eq "integration") {
    # Test IT1: HTTP timeout returns Status=0, Body=null
    # Endpoint dead-drop que aceita conexão mas nunca responde:
    # https://httpstat.us/200?sleep=30000 (dorme 30s > timeout 10s)
    $out = & $exe --community-http-probe "https://httpstat.us/200?sleep=30000" 2>&1
    if ($out -notmatch "Status=0") { Write-Error "FAIL: timeout should return Status=0 ($out)"; exit 1 }
    Write-Host "PASS: HTTP timeout handled"

    # Test IT2: pull-once retorna dados do Supabase
    if (-not $env:WSE_URL -or -not $env:WSE_KEY) {
        Write-Warning "Skip pull test - set WSE_URL and WSE_KEY env vars"
    } else {
        # Push 1 entry via Invoke-WebRequest → asserta pull no client.
        $body = '[{"entity_id":6893474,"nick":"Centablg","class_id":10,"client_id":"test-runner"}]'
        $r = Invoke-WebRequest -Uri "$env:WSE_URL/rest/v1/entities?on_conflict=entity_id" `
            -Method POST -Body $body -ContentType "application/json" `
            -Headers @{ "apikey" = $env:WSE_KEY; "Authorization" = "Bearer $env:WSE_KEY"; "Prefer" = "resolution=merge-duplicates,return=minimal" }
        if ($r.StatusCode -ne 201) { Write-Error "FAIL: seed push status=$($r.StatusCode)"; exit 1 }

        # Roda --community-pull-once (branch adicionado na Task 8)
        $out = & $exe --community-pull-once $env:WSE_URL $env:WSE_KEY 2>&1
        if ($out -notmatch "pulled=\d+") { Write-Error ("FAIL: expected pulled=N, got: " + $out); exit 1 }
        Write-Host ("PASS: pull-once (" + $out + ")")
    }

    # Test IT3: heartbeat — client row upsertado em /clients
    if (-not $env:WSE_URL -or -not $env:WSE_KEY) {
        Write-Warning "SKIP IT3: heartbeat integration - set WSE_URL and WSE_KEY env vars"
    } else {
        $root = Split-Path $exe -Parent
        $cidFile = Join-Path $root "ws-engine.client-id.txt"
        $meFile  = Join-Path $root "ws-engine.me.txt"
        $cidBak  = if (Test-Path $cidFile) { Get-Content $cidFile -Raw } else { $null }
        $meBak   = if (Test-Path $meFile)  { Get-Content $meFile  -Raw } else { $null }
        try {
            # Limpa o client hb-test-client anterior se existir
            try {
                Invoke-WebRequest -Uri "$env:WSE_URL/rest/v1/clients?client_id=eq.hb-test-client" `
                    -Method DELETE `
                    -Headers @{ "apikey" = $env:WSE_KEY; "Authorization" = "Bearer $env:WSE_KEY" } | Out-Null
            } catch { }

            $out = & $exe --community-hb-once $env:WSE_URL $env:WSE_KEY 2>&1
            if ($LASTEXITCODE -ne 0) { Write-Error "FAIL IT3: hb-once exit=$LASTEXITCODE out=$out"; exit 1 }

            # Verifica via HTTP que client apareceu
            $r = Invoke-WebRequest -Uri "$env:WSE_URL/rest/v1/clients?client_id=eq.hb-test-client&select=*" `
                -Headers @{ "apikey" = $env:WSE_KEY; "Authorization" = "Bearer $env:WSE_KEY" }
            if ($r.Content -notmatch "hb-test-client") { Write-Error "FAIL IT3: client not registered (got: $($r.Content))"; exit 1 }
            Write-Host "PASS: heartbeat integration (IT3)"
        } finally {
            if ($cidBak) { Set-Content -Path $cidFile -Value $cidBak } elseif (Test-Path $cidFile) { Remove-Item $cidFile }
            if ($meBak)  { Set-Content -Path $meFile  -Value $meBak  } elseif (Test-Path $meFile)  { Remove-Item $meFile  }
        }
    }
}
