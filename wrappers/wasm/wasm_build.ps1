$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$crateRoot = (Resolve-Path (Join-Path $scriptRoot '..\..')).Path
$distRoot = Join-Path $scriptRoot 'dist'

function Invoke-WasmPackBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$OutDir
    )

    & wasm-pack build $crateRoot --out-dir $OutDir --target $Target --scope devolutions -- --features=wbindgen

    if ($LASTEXITCODE -ne 0) {
        throw "wasm-pack build failed for target '$Target' with exit code $LASTEXITCODE."
    }
}

Invoke-WasmPackBuild -Target 'bundler' -OutDir (Join-Path $distRoot 'bundler')
Invoke-WasmPackBuild -Target 'nodejs' -OutDir (Join-Path $distRoot 'node')
Invoke-WasmPackBuild -Target 'web' -OutDir (Join-Path $distRoot 'web')
Invoke-WasmPackBuild -Target 'no-modules' -OutDir (Join-Path $distRoot 'no-modules')

$webPackageJsonPath = Join-Path $distRoot 'web\package.json'
$webPackageJson = Get-Content $webPackageJsonPath -Raw | ConvertFrom-Json
$webPackageJson.name = '@devolutions/devolutions-crypto-web'
$webPackageJson | ConvertTo-Json -Depth 10 | Set-Content $webPackageJsonPath
