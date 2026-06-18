# Windows Software Inventory Analyzer

Windows Software Inventory Analyzer, bir Windows sistemindeki kurulu uygulamalari, disk klasorlerini ve gelistirme projeleriyle iliskili araclari analiz etmek icin tasarlanmis read-only bir aractir.

Ilk surumun hedefi:

- kurulu yazilim envanterini toplamak
- proje klasorlerini sonradan taramaya hazir hale getirmek
- analiz kurallarini config ile yonetmek
- hicbir dosya veya programi silmeden raporlama altyapisi saglamak

## Guvenlik Prensibi

Bu proje ilk surumde **strictly read-only** calisir.

- Dosya silmez
- Program kaldirmaz
- Registry veya disk uzerinde degisiklik yapmaz
- Sadece okuma, siniflandirma ve raporlama amaciyla tasarlanmistir

Kod tarafinda yapilan her islem bu prensibe uygun tutulmalidir.

## Proje Yapisi

```text
windows-software-inventory-analyzer/
|-- .venv/
|-- config.example.yaml
|-- data/
|   `-- sample/
|       `-- installed_programs.sample.json
|-- main.py
|-- requirements.txt
`-- src/
    `-- windows_software_inventory_analyzer/
        |-- __init__.py
        |-- app.py
        |-- config.py
        |-- logging_config.py
        `-- models.py
```

## Kurulum

Windows PowerShell:

```powershell
& "C:\msys64\ucrt64\bin\python.exe" -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item config.example.yaml config.yaml
python main.py --config config.yaml
```

Not:

- Bu ortamda `python.exe` cagrisinda sorun goruldugu icin yorumlayici olarak `C:\msys64\ucrt64\bin\python.exe` kullanildi.
- Normal bir Windows Python kurulumunda dogrudan `python` veya `py` ile de calisabilir.

## Konfigurasyon

`config.example.yaml` su alanlari icerir:

- `scan.disks`: taranacak suruculer
- `scan.project_roots`: proje klasorlerinin kokleri
- `scan.exclude_paths`: tarama disi tutulacak klasorler
- `report.output_dir`: rapor klasoru
- `behavior.read_only`: guvenlik bayragi, her zaman `true` kalmali

## Calistirma

Varsayilan olarak:

```powershell
python main.py
```

Belirli bir config ile:

```powershell
python main.py --config config.yaml
```

Uygulama su an:

- config dosyasini yukler
- logging ayarini yapar
- read-only modunu dogrular
- ozet bilgiyi ekrana ve loga yazar

Sprint 0'da harici Python bagimliligi yoktur. `requirements.txt` bilincli olarak bos bir baslangic dosyasidir.

## Sonraki Sprintler

- Windows registry uzerinden kurulu uygulama envanteri toplama
- Disk kullanimi ve klasor siniflandirma
- Proje bagimliliklarini tespit etme
- Anahtar kelime tabanli arama ve kategori esleme
- HTML/JSON raporlama
