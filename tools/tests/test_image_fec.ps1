$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")

function Try-CMakeImageFecTest {
    $cmake = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if (-not $cmake) {
        return $false
    }

    $cmakeBuildDir = Join-Path $Root "build\cmake-mingw"
    $cachePath = Join-Path $cmakeBuildDir "CMakeCache.txt"
    if (-not (Test-Path $cachePath)) {
        $ninja = Get-Command ninja.exe -ErrorAction SilentlyContinue
        $gcc = Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue
        $windres = Get-Command windres.exe -ErrorAction SilentlyContinue
        $ar = Get-Command x86_64-w64-mingw32-gcc-ar.exe -ErrorAction SilentlyContinue
        $ranlib = Get-Command x86_64-w64-mingw32-gcc-ranlib.exe -ErrorAction SilentlyContinue
        if (-not ($ninja -and $gcc -and $windres -and $ar -and $ranlib)) {
            return $false
        }
        & $cmake.Source -S $Root -B $cmakeBuildDir -G Ninja `
            -DCMAKE_BUILD_TYPE=Release `
            "-DCMAKE_C_COMPILER=$($gcc.Source)" `
            "-DCMAKE_RC_COMPILER=$($windres.Source)" `
            "-DCMAKE_AR=$($ar.Source)" `
            "-DCMAKE_RANLIB=$($ranlib.Source)" `
            "-DCMAKE_C_COMPILER_AR=$($ar.Source)" `
            "-DCMAKE_C_COMPILER_RANLIB=$($ranlib.Source)" `
            -DCMAKE_C_COMPILER_WORKS=TRUE `
            -DCMAKE_C_COMPILER_FORCED=TRUE `
            -DCMAKE_C_ABI_COMPILED=TRUE `
            -DCMAKE_RC_COMPILER_WORKS=TRUE
        if ($LASTEXITCODE -ne 0) {
            throw "image_fec_test CMake configure failed"
        }
    }

    & $cmake.Source --build $cmakeBuildDir --target image_fec_test --config Release
    if ($LASTEXITCODE -ne 0) {
        throw "image_fec_test CMake target build failed"
    }

    $exe = Join-Path $Root "build\image_fec_test.exe"
    if (-not (Test-Path $exe)) {
        throw "image_fec_test CMake target did not produce $exe"
    }
    & $exe
    if ($LASTEXITCODE -ne 0) {
        throw "image_fec_test failed"
    }
    return $true
}

Push-Location $Root
try {
    if (-not (Try-CMakeImageFecTest)) {
        Write-Host "skip image_fec_test: CMake/MinGW toolchain unavailable"
    }
} finally {
    Pop-Location
}
