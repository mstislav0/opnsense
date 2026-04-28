#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Экспорт пользователей из AD-группы в JSON для передачи на OPNsense.

.DESCRIPTION
    Скрипт ищет группу в Active Directory по введённой строке,
    предлагает выбрать из найденных, затем выгружает список активных
    пользователей в JSON-файл. Этот файл передаётся на OPNsense и
    используется скриптом 2_create_vpn_certs.py для создания сертификатов и CSO.

.NOTES
    Требования: Windows с RSAT (модуль ActiveDirectory), права чтения AD.
    Выходной файл: users_<GroupName>_<Date>.json
#>

# ─────────────────────────────────────────────────────────────────────
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ─────────────────────────────────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    $line = "=" * 60
    Write-Host ""
    Write-Host $line              -ForegroundColor Cyan
    Write-Host "  $Text"         -ForegroundColor Cyan
    Write-Host $line              -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] $Text"
}

# ─────────────────────────────────────────────────────────────────────
#  ПРОВЕРКА МОДУЛЯ AD
# ─────────────────────────────────────────────────────────────────────

Write-Header "Экспорт пользователей AD → JSON для VPN"

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "[ОШИБКА] Модуль ActiveDirectory не найден." -ForegroundColor Red
    Write-Host "Установите RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop
Write-Step "Модуль ActiveDirectory загружен."

# ─────────────────────────────────────────────────────────────────────
#  ШАГ 1 — ПОИСК ГРУППЫ
# ─────────────────────────────────────────────────────────────────────

Write-Header "Шаг 1: Поиск группы"

$foundGroups = @()

do {
    $searchQuery = (Read-Host "Введите часть имени группы для поиска").Trim()

    if ([string]::IsNullOrEmpty($searchQuery)) {
        Write-Host "[!] Строка не может быть пустой." -ForegroundColor Yellow
        continue
    }

    Write-Step "Ищу группы содержащие '$searchQuery'..."

    try {
        $foundGroups = @(Get-ADGroup -Filter "Name -like '*$searchQuery*'" `
            -Properties Name, Description, GroupScope -ErrorAction Stop |
            Sort-Object Name)
    } catch {
        Write-Host "[ОШИБКА] $_" -ForegroundColor Red
        continue
    }

    if ($foundGroups.Count -eq 0) {
        Write-Host "[!] Ничего не найдено. Попробуйте другой запрос." -ForegroundColor Yellow
    }

} while ($foundGroups.Count -eq 0)

# ─────────────────────────────────────────────────────────────────────
#  ШАГ 2 — ВЫБОР ГРУППЫ
# ─────────────────────────────────────────────────────────────────────

Write-Header "Шаг 2: Выбор группы"

Write-Host "Найдено: $($foundGroups.Count) групп(ы)`n"

for ($i = 0; $i -lt $foundGroups.Count; $i++) {
    $g    = $foundGroups[$i]
    $desc = if ($g.Description) { $g.Description } else { "—" }
    Write-Host ("  [{0,2}] {1,-40} | {2,-12} | {3}" -f ($i+1), $g.Name, $g.GroupScope, $desc)
}

Write-Host ""
$choiceNum = 0
do {
    $input = Read-Host "Введите номер группы (1-$($foundGroups.Count))"
    if (-not [int]::TryParse($input, [ref]$choiceNum) -or
        $choiceNum -lt 1 -or $choiceNum -gt $foundGroups.Count) {
        Write-Host "[!] Введите число от 1 до $($foundGroups.Count)." -ForegroundColor Yellow
        $choiceNum = 0
    }
} while ($choiceNum -lt 1)

$selectedGroup = $foundGroups[$choiceNum - 1]
Write-Step "Выбрана: '$($selectedGroup.Name)'"

# ─────────────────────────────────────────────────────────────────────
#  ШАГ 3 — ПОЛУЧЕНИЕ ПОЛЬЗОВАТЕЛЕЙ
# ─────────────────────────────────────────────────────────────────────

Write-Header "Шаг 3: Получение пользователей"

Write-Step "Загружаю участников (рекурсивно)..."

try {
    # Recursive — включает участников вложенных групп
    $members = @(Get-ADGroupMember -Identity $selectedGroup.DistinguishedName `
        -Recursive -ErrorAction Stop |
        Where-Object { $_.objectClass -eq "user" })
} catch {
    Write-Host "[ОШИБКА] $_" -ForegroundColor Red
    exit 1
}

if ($members.Count -eq 0) {
    Write-Host "[!] Группа не содержит пользователей." -ForegroundColor Yellow
    exit 0
}

Write-Step "Найдено учётных записей: $($members.Count). Загружаю атрибуты..."

$userObjects = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($m in $members) {
    try {
        $u = Get-ADUser -Identity $m.SamAccountName `
            -Properties SamAccountName, GivenName, Surname, EmailAddress, `
                        UserPrincipalName, Enabled -ErrorAction Stop

        # Пропускаем отключённые аккаунты
        if (-not $u.Enabled) {
            Write-Host "  [SKIP] $($u.SamAccountName) — отключён" -ForegroundColor DarkGray
            continue
        }

        # Email: берём из AD, иначе строим из UPN, иначе username@lab.local
        $email = if ($u.EmailAddress) {
            $u.EmailAddress
        } elseif ($u.UserPrincipalName -match "@") {
            $u.UserPrincipalName
        } else {
            "$($u.SamAccountName)@lab.local"
        }

        $userObjects.Add([PSCustomObject]@{
            username     = $u.SamAccountName
            email        = $email
            source_group = $selectedGroup.Name
        })

    } catch {
        Write-Host "  [WARN] $($m.SamAccountName): $_" -ForegroundColor Yellow
    }
}

if ($userObjects.Count -eq 0) {
    Write-Host "[!] Нет активных пользователей для экспорта." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Итоговый список:" -ForegroundColor Cyan
$userObjects | Format-Table -AutoSize username, email

# ─────────────────────────────────────────────────────────────────────
#  ШАГ 4 — СОХРАНЕНИЕ JSON
# ─────────────────────────────────────────────────────────────────────

Write-Header "Шаг 4: Сохранение"

$safeName   = $selectedGroup.Name -replace '[^\w\-]', '_'
$dateStamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "users_${safeName}_${dateStamp}.json"
$outputPath = Join-Path (Get-Location) $outputFile

try {
    $userObjects | ConvertTo-Json -Depth 3 |
        Out-File -FilePath $outputPath -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Host "[ОШИБКА] Не удалось сохранить файл: $_" -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────────────────────────────
#  ИТОГ
# ─────────────────────────────────────────────────────────────────────

Write-Header "Готово"
Write-Host "  Группа        : $($selectedGroup.Name)"   -ForegroundColor White
Write-Host "  Пользователей : $($userObjects.Count)"    -ForegroundColor Green
Write-Host "  Файл          : $outputPath"              -ForegroundColor Green
Write-Host ""
Write-Host "Следующий шаг: скопируйте файл на OPNsense и запустите:" -ForegroundColor Cyan
Write-Host "  python3 /root/2_create_vpn_certs.py $outputFile" -ForegroundColor Yellow
Write-Host "  # или без интерактива:" -ForegroundColor DarkGray
Write-Host "  python3 /root/2_create_vpn_certs.py --yes --tunnel 10.8.X.0/24 --ca VPN-CA-Name $outputFile" -ForegroundColor DarkGray
Write-Host ""
