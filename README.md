# Windows Software Inventory Analyzer

Windows Software Inventory Analyzer, Windows makinedeki kurulu yazilimlari, buyuk klasorleri, proje bagimliliklarini ve program-proje iliskilerini read-only sekilde analiz eder. Amac, kullaniciya "bu program gerekli mi, belirsiz mi, manuel mi bakmaliyim?" sorularinda karar destegi vermektir.

## Guvenlik

Bu proje varsayilan olarak **read-only** calisir.

- Dosya silmez
- Program kaldirmaz
- Registry veya sistem ayarlarini degistirmez
- Yalnizca tarama, eslestirme, raporlama ve dashboard gosterimi yapar

Nihai karar her zaman kullanicidadir.

## Kurulum

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
Copy-Item config.example.yaml config.yaml
```

Bu ortamda sanal ortam `bin` yapisiyla olusuyorsa:

```powershell
& ".\.venv\bin\python.exe" -m pip install -r requirements.txt
```

## Ilk Config Ornegi

`config.example.yaml` mevcut yapida asagidaki alanlari kullanir:

```yaml
scan:
  disks:
    - "C:\\"
  project_roots:
    - "D:\\Github"
    - "D:\\Projects"
    - "%USERPROFILE%\\source\\repos"
  disk_usage_roots:
    - "C:\\Program Files"
    - "C:\\Program Files (x86)"
    - "%LOCALAPPDATA%"
    - "%APPDATA%"
  exclude_paths:
    - "C:\\Windows"
    - "C:\\ProgramData\\Microsoft"
    - "C:\\$Recycle.Bin"
  max_depth: 4

report:
  output_dir: "./data/output"
  formats:
    - "csv"
    - "json"

logging:
  level: "INFO"
  log_to_file: false
  log_dir: "./data/output/logs"

behavior:
  read_only: true
  allow_delete: false
  allow_uninstall: false
```

## Kullanim

Tum pipeline:

```powershell
python -m src.main --config config.yaml
```

Onerilen komutlar:

```powershell
python -m src.main collect-programs --config config.yaml
python -m src.main scan-disk --config config.yaml
python -m src.main scan-projects --config config.yaml
python -m src.main map-software --config config.yaml
python -m src.main recommend --config config.yaml
```

Dry-run:

```powershell
python -m src.main recommend --config config.yaml --dry-run
```

Verbose:

```powershell
python -m src.main scan-projects --config config.yaml --verbose
```

Legacy giris noktasi hala calisir:

```powershell
python main.py
```

## Dashboard

Dashboard acmak icin:

```powershell
python dashboard.py
```

Alternatif:

```powershell
streamlit run dashboard.py
```

Sadece statik HTML rapor ve export dosyalari uretmek icin:

```powershell
python dashboard.py --build-report
```

## Test

Pytest ile:

```powershell
python -m pytest -q
```

Testler su senaryolari kapsar:

- bozuk `package.json`
- eksik CSV dosyasi
- bos proje klasoru
- `PermissionError` benzeri klasor erisim hatasi
- non-Windows registry fallback davranisi
- CLI dry-run akisi

## Uretilen Ciktilar

`data/output/` altinda:

- `installed_programs.csv`
- `installed_programs.json`
- `disk_usage.csv`
- `developer_caches.csv`
- `project_tech_stack.csv`
- `project_files_index.csv`
- `software_project_mapping.csv`
- `recommendations.csv`

Ek raporlar:

- `report.html`
- `exports/`
- `sample_reports/`

## Karar Mantigi

- Aktif projede kanit varsa: `KEEP`
- Sistem/runtime/surucu bileseni ise: `MANUAL_REVIEW`
- Buyuk alan kapliyor ama iliski zayifsa: `UNSURE`
- Belirsiz ve proje iliskisi yoksa: `CAN_REMOVE` veya `MANUAL_REVIEW`
- Unknown kategoriler: her zaman `MANUAL_REVIEW`

Korumali bilesenler icin dogrudan sil onerisi verilmez:

- Microsoft Visual C++ Redistributable
- .NET Runtime / SDK
- GPU driver
- chipset / audio / temel surucu bilesenleri
- Windows SDK

## MVP Sorulari

Bu surum su sorulara cevap vermeyi hedefler:

- Hangi programlar yüklü?
- En cok yer kaplayan klasorler hangileri?
- Projelerde hangi teknolojiler kullanilmis?
- Python, Docker, Node.js gibi araclar hangi projelerle iliskili?
- Hangi programlar tutulmali, hangileri manuel incelenmeli?
- Anahtar kelime arandiginda ilgili program ve projeler geliyor mu?
