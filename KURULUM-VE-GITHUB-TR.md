# LANORA — ikon, Windows kurulumu ve GitHub

Bu paket, gönderdiğiniz 1.2.0 kaynak kodunu temel alır. Tarama motoruna yönelik
bir değişiklik yapılmadı. İkon ve dağıtım hazırlığı eklendi. Windows kurulum
programı henüz çalıştırılarak doğrulanmadı; hazır kurulum EXE'si içermez.

## 1. İkon

Arayüzün koyu yeşili `#173C33`, ana yeşili `#2D7659` ve açık yeşili `#C6EEA3`
kullanıldı. Kalkan güvenliği; onay şeklinde birbirine bağlanan üç nokta ağın
gözlemlenmesini temsil eder. Mevcut SVG marka dili korundu.

`src/Lanora/Assets/` klasöründe:

- `Lanora.svg`: düzenlenebilir vektör kaynak.
- `Lanora.png`: saydam zeminli 1024 × 1024 PNG.
- `Lanora.ico`: 16, 20, 24, 32, 40, 48, 64, 96, 128 ve 256 piksel katmanları.

İkon EXE kaynağına ve sistem tepsisine bağlandı; tarayıcı favicon'u, yan menü
ve Hakkında alanı aynı grafiği kullanır. Yeni EXE'yi derleyince etkinleşir.
Windows eski simgeyi önbellekten gösterebilir; yeni derlemeyi farklı bir klasörde
kontrol edin. Önceki ZIP'teki derlenmiş EXE bu kaynak paketinde yer almaz.

## 2. Windows kurulum dosyası oluşturma

Windows'a [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) ve
[Inno Setup](https://jrsoftware.org/isdl.php) kurun. Inno Setup'ın preprocessor
bileşenini koruyun. ZIP'i çıkartın; `Lanora.slnx` dosyasının bulunduğu `Lanora`
klasöründe PowerShell açın:

```powershell
dotnet test Lanora.slnx -c Debug
node tests/frontend/frontend-checks.cjs
.\packaging\Build-Windows.ps1
```

Frontend kontrolü için Node.js gerekir. Betik ayrıca test çalıştırmaz; ilk iki
komutta hata varsa önce düzeltin. PowerShell indirilen dosyayı engellerse,
içeriğini gözden geçirdikten sonra yalnızca bu projedeki betiği Dosya
Özellikleri'nden engelini kaldırarak çalıştırın; genel güvenlik ayarlarını
kapatmayın.

Çıktılar `dist/installer/` klasöründedir:

| Dosya | Kullanımı |
|---|---|
| `Lanora-1.2.0-Setup-x64.exe` | Kurulum sihirbazı, Başlat menüsü, isteğe bağlı masaüstü kısayolu ve kaldırma |
| `Lanora-1.2.0-Portable-x64.zip` | Kurulumsuz kullanım |
| `SHA256SUMS.txt` | İndirilen dosyaların SHA-256 değerleri |

Kurulum kullanıcı hesabına yapılır; yönetici izni istemez. Kullanıcıda ayrıca
.NET bulunması gerekmez. Kurulum hedefi `%LOCALAPPDATA%\Programs\Lanora`, veri
konumu `%LOCALAPPDATA%\Lanora` olur. Kaldırma kullanıcı verisini silmez. Güncelleme
ve kaldırma öncesinde uygulamadan sistem tepsisi menüsüyle çıkın. Sonraki
sürümlerde `.csproj` içindeki Version'ı değiştirin; `Lanora.iss` içindeki AppId'yi
aynı bırakın.

Bu bir **Setup.exe** çözümüdür. Kurumsal dağıtımda özellikle MSI istenirse aynı
publish çıktısını WiX Toolset gibi bir araçla MSI olarak paketlemek gerekir.
Dosya uzantısını değiştirmek dönüştürme yapmaz. Hazırlanan betik MSI üretmez.

## 3. “Bilinmeyen yayıncı” ve SmartScreen

Kurulum paketi hazırlamak yayıncı kimliğini doğrulamaz. Bunun için güvenilir
bir sağlayıcının **kod imzalama** kimliği gerekir; web sitesi TLS sertifikası
bu amaç için yeterli değildir.

- Geçerli Authenticode imzası Windows'ta doğrulanmış yayıncı adını sağlar.
- “Windows bilgisayarınızı korudu” SmartScreen uyarısı dosya/yayıncı itibarını
  da değerlendirir. Yeni ve imzalı bir sürümde bile görülebilir.
- Kendi oluşturduğunuz sertifika genel kullanıcılarda güven sorununu çözmez.
- EV sertifikasının artık SmartScreen'i otomatik kaldırma garantisi yoktur.
- Her sürümde tutarlı yayıncı kimliği kullanın; zaman damgası ekleyin ve imzadan
  sonra EXE'yi değiştirmeyin.

İki yol vardır:

**Sertifika deposu / token / HSM:** Doğrulanmış kod imzalama sertifikasını ve
Windows SDK'daki SignTool'u hazırlayın. Ardından:

```powershell
.\packaging\Build-Windows.ps1 `
  -Publisher 'DOGRULANMIS YAYINCI ADINIZ' `
  -CertificateThumbprint 'SERTIFIKANIN_THUMBPRINT_DEGERI' `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\SDK_SURUMU\x64\signtool.exe'
```

Sertifika kullanıcının Personal/My deposunda, özel anahtarı sağlayıcısında
bulunmalıdır. Betik önce uygulamayı, ardından Inno Setup aracılığıyla kaldırma
ve kurulum programını imzalar. Gerçek bir sertifika bu pakete dahil değildir.

**Microsoft Artifact Signing:** Azure'da hesap, kimlik doğrulaması ve Public
Trust sertifika profili hazırlayın; resmi SignTool/Actions entegrasyonunu
kullanın. Almanya gibi AB ülkelerindeki uygun kuruluşlar başvurabilir.
20.10.2026 itibarıyla bireysel geliştirici Public Trust başvuruları ABD/Kanada
ile sınırlıdır. Abonelik almadan önce uygunluğu doğrulayın. Bu paketteki
sertifika deposu betiği Azure imzasını otomatik yapılandırmaz.

İmza sırası: uygulamayı derle → uygulamayı imzala → imzalı kaldırıcıyı ve kurulum
paketini üret → kurulum imzasını doğrula → son dosyaları yayımla.

## 4. GitHub'a kaynak kodu yükleme

Önce kaynak kodunu herkese açık mı, özel mi tutacağınızı belirleyin. Açık kaynak
olarak paylaşacaksanız tercih ettiğiniz lisansı ekleyin; adınıza lisans seçilmedi.
`THIRD-PARTY-NOTICES.md` dosyasını koruyun. Lisans metinleri ve dağıtılan bağımlılık
bildirimlerini genel yayımdan önce tamamlayın.

1. GitHub'da yeni, boş bir `Lanora` deposu oluşturun. Elinizde README ve gitignore
   bulunduğu için oluşturma sırasında bunları yeniden eklemeyin.
2. `Lanora.slnx` bulunan klasörü depo kökü yapın. `.github/` klasörünü de yükleyin.
3. Git kurulu bir terminalde aşağıdaki komutları çalıştırın. `KULLANICI_ADINIZ`
   kısmını değiştirin:

```powershell
git init
git branch -M main
git add .
git status
git commit -m "Prepare LANORA 1.2.0 distribution"
git remote add origin https://github.com/KULLANICI_ADINIZ/Lanora.git
git push -u origin main
```

`git status` çıktısında yalnızca paylaşacağınız kaynaklar olmalı. Veritabanı,
kullanıcı tarama sonuçları, günlükler, tokenlar, özel anahtarlar ve sertifika
parolalarını yüklemeyin. `.gitignore`, `bin/`, `obj/`, `dist/`, DB ve özel anahtar
uzantılarını dışlar. Önceden Git'e alınmış dosyaları gitignore geriye dönük
kaldırmaz. Mevcut bir Git deponuz varsa `init/remote add` adımlarını tekrarlamak
yerine mevcut origin'i kontrol edin. GitHub oturumu için Git Credential Manager
veya GitHub CLI kullanabilirsiniz; parola/tokenı kaynak dosyasına yazmayın.

## 5. GitHub üzerinden Setup.exe üretme

Windows bilgisayarınızda derleme yapmak istemezseniz eklenen iş akışını kullanın:

1. Depodaki **Actions** sekmesini açın.
2. **Windows installer (unsigned)** iş akışını seçin.
3. **Run workflow** düğmesine basın.
4. Başarıyla tamamlanan çalışmanın **Artifacts** bölümünden
   `Lanora-Windows-unsigned` arşivini indirin.

İş akışı Windows üzerinde C# ve frontend testlerini çalıştırır, EXE'yi derler,
Inno Setup ile kurulum paketini oluşturur. Çıktılar 14 gün saklanır. Bu iş akışı
**imzasız** dosyalar üretir; imzalama kimliği ayrıca kurulmalıdır. Workflow sadece
okuma iznine sahiptir ve kendiliğinden herkese açık bir Release yayımlamaz.

## 6. Kullanıcıların indireceği sürümü yayımlama

Kaynak kodu Git deposunda, çalıştırılabilir dosyalar **Releases** bölümünde tutulur.

1. GitHub'da **Releases → Draft a new release** seçin.
2. Etiket olarak `v1.2.0`, hedef olarak `main` seçin/oluşturun.
3. Başlığa `LANORA 1.2.0` yazıp değişiklikleri ve Windows x64 gereksinimini ekleyin.
4. Oluşturulan Setup.exe, Portable ZIP ve `SHA256SUMS.txt` dosyalarını ekleyin.
5. İmzalama kullanıyorsanız son, doğrulanmış imzalı dosyaları yükleyin. Sertifika
   anahtarlarını eklemeyin. İmzasız beta ise bunu sürüm notunda açıkça belirtin.
6. İndirme, kurulum, ilk açılış, tepsi ikonu, tarama/rapor, yükseltme ve kaldırmayı
   temiz bir Windows 11 bilgisayarda deneyin; ardından **Publish release** seçin.

Sadece indirme dağıtmak istiyorsanız kaynak kodunu herkese açmanız gerekmez;
hassas kaynakları içermeyen ayrı bir dağıtım deposunda Releases kullanabilirsiniz.
GitHub Pages Windows uygulamasını çalıştırmaz; indirme/tanıtım sayfası olabilir.

## Hazırlama sırasında doğrulananlar

- Windows x64 Release derlemesi: 0 hata, 0 uyarı.
- Bağımsız Windows x64 publish: başarılı; ikon kaynakları dahil.
- JavaScript sözdizimi ve mevcut 10 frontend kontrolü: başarılı.
- Ayrı Linux uyumlu test kopyasında mevcut 74 C# testi: başarılı. Masaüstü giriş
  noktası hariç tutuldu; PDF testlerinde yerel test fontları kullanıldı.
- Windows tepsisi, kurulum/kaldırma, gerçek imza sağlayıcısı ve GitHub workflow
  çalışması bu ortamda denenmedi. Bu çalışma yeni bir güvenlik denetimi değildir.

## Resmî kaynaklar

- [.NET tek EXE yayımlama](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview)
- [Inno Setup](https://jrsoftware.org/isdl.php)
- [Inno Setup imzalama](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)
- [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [SmartScreen itibarı](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [Artifact Signing kurulumu/uygunluk](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
- [GitHub'a yerel kod ekleme](https://docs.github.com/get-started/importing-your-projects-to-github/importing-source-code-to-github/adding-locally-hosted-code-to-github)
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
