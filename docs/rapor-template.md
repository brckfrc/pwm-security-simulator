# Proje Raporu: Parola Yöneticilerinde KDF ve Vault Bütünlüğü Güvenlik Simülasyonu

## Proje Amacı

Bu proje, modern parola yöneticilerinin güvenliğinde kritik rol oynayan iki temel kavramı göstermek amacıyla geliştirilmiş eğitsel bir simülatördür:

1. **Anahtar Türetme Fonksiyonu (KDF):** Ana parolanın şifreleme anahtarına nasıl dönüştürüldüğü ve iterasyon sayısının brute-force saldırılarına direnci nasıl etkilediği.
2. **Vault Bütünlüğü:** Şifrelemenin tek başına yeterli olmadığı ve vault dosyasına yapılan müdahalelerin nasıl tespit edilebileceği (ya da edilemeyeceği).

Tüm demolar yerel olarak üretilmiş sahte veriler üzerinde gerçekleştirilmiştir. Gerçek bir parola yöneticisine, kullanıcı verisine veya üretim sistemine erişilmemiştir.

---

## Tehdit Modeli

Simülasyon, saldırganın **ana parolayı bilmediği** ancak vault dosyasına **durağan halde (at-rest) okuma ve yazma erişimi** olduğu bir senaryoyu varsayar. Bu, gerçek dünyada şu durumlara karşılık gelir: çalınmış bir cihaz yedeği, kötü niyetli veya ele geçirilmiş bir bulut senkronizasyon sunucusu ya da paylaşılan bir bilgisayardaki vault dosyası. Saldırgan içeriği şifre çözemez, fakat şifreli baytları, KDF parametrelerini veya sürüm bilgisini değiştirebilir.

Bu tehdit modelinde **bütünlük (integrity)**, gizlilik kadar kritiktir: saldırgan vault'u doğrudan okuyamasa bile, bütünlük koruması yoksa şifreli veriyi manipüle ederek (bit çevirme), kripto parametrelerini zayıflatarak veya eski bir durumu geri yükleyerek sistemi sessizce bozabilir. Bu raporda karşılaştırılan güvensiz ve güvenli tasarımlar tam olarak bu yetenekler üzerinden değerlendirilir.

---

## KDF (Anahtar Türetme Fonksiyonu)

### PBKDF2-HMAC-SHA256

PBKDF2, ana parolayı belirli bir iterasyon sayısıyla tekrar tekrar hashleyerek bir şifreleme anahtarı üretir. İterasyon sayısı ne kadar yüksekse, her aday parola için gereken hesaplama maliyeti o kadar artar:

Apple M4 üzerinde ölçülen anahtar türetme süreleri:

| Konfigürasyon | Ölçülen Süre |
|---|---|
| PBKDF2 – 1.000 iter | ~0,2 ms |
| PBKDF2 – 100.000 iter | ~19 ms |
| PBKDF2 – 600.000 iter | ~113 ms |
| Argon2id (t=3, m=64 MiB, p=1) | ~90 ms |

600.000 iterasyonda saldırgan, 1.000 iterasyona kıyasla her deneme için yaklaşık 500–600× daha fazla iş yapmak zorundadır (sabit ek yük çıkarıldığında oran iterasyon oranına yaklaşır). NIST ve OWASP bu değeri (veya daha yükseklerini) önermektedir.

### Argon2id

Argon2id, CPU süresi yanı sıra bellek maliyeti de ekleyen, GPU/ASIC tabanlı paralel saldırılara karşı dayanıklı bir KDF'dir. Bitwarden ve Vaultwarden gibi modern parola yöneticileri PBKDF2'den Argon2id'ye geçiş yapmaktadır. Simülatörde t=3, m=64 MiB, p=1 parametreleriyle yaklaşık 90 ms süre ölçülmüştür — tek başına bu süre PBKDF2 600.000 iterasyonla benzerdir, fakat her denemenin 64 MiB bellek gerektirmesi, GPU farmlarıyla paralel kırma işlemini son derece maliyetli hale getirir. Simülatörde KDF seçimi kullanıcıya bırakılmıştır; seçilen KDF ve parametreleri kasa dosyasına yazılır ve güvenli modda AAD ile bütünlük koruması altına alınır.

---

## Vault Bütünlüğü

### Güvensiz Tasarım: AES-CTR (MAC yok)

AES-CTR modunda vault şifrelenir ancak bütünlük koruması uygulanmaz. KDF parametreleri (salt, iterasyon sayısı) düz metin olarak saklanır ve şifreli metinle kriptografik olarak ilişkilendirilmez.

**Sonuç:** Saldırgan vault dosyasını değiştirse bile sistem bu değişikliği fark etmez:

- **Bit çevirme:** Şifreli metindeki bir baytın çevrilmesi, anahtar bilinmeden düz metinde öngörülebilir bir değişikliğe yol açar.
- **KDF parametresi düşürme:** İterasyon sayısı 1.000'e indirilebilir; sistem hata vermez, yalnızca yanlış anahtar türeterek garip veri döner.
- **Replay saldırısı:** Eski bir vault anlık görüntüsü sessizce kabul edilir.

### Güvenli Tasarım: AES-GCM (AEAD)

AES-GCM, şifreleme ve bütünlük doğrulamasını tek adımda sağlar. Vault sürüm numarası ve KDF parametreleri **associated data (AAD)** olarak iletilir; böylece bu alanlar şifrelenmese de kimlik doğrulamasına dahil edilir. Vault dosyasındaki herhangi bir **yerinde (in-place) değişiklik** — şifreli metin, kimlik doğrulama etiketi, KDF parametreleri veya sürüm numarası — GCM etiketini geçersiz kılar ve sistem `IntegrityError` fırlatır.

Önemli bir sınır: AAD yalnızca tek bir vault dosyasının kendi içindeki tutarlılığını doğrular. Bu nedenle, eski ama geçerli biçimde şifrelenmiş bir vault dosyasının tamamıyla geri yüklendiği **tam dosya replay (rollback)** saldırısı AAD tarafından tespit edilemez; bu saldırıya karşı koruma, vault dosyasının dışında tutulan harici bir monoton sürüm sayacı gerektirir.

---

## Kullanılan Teknolojiler

| Teknoloji | Kullanım Amacı |
|---|---|
| Python 3.10+ | Ana programlama dili |
| Streamlit 1.58 | Yerel web arayüzü |
| `cryptography` 49.0 | PBKDF2, AES-CTR, AES-GCM |
| `argon2-cffi` 25.1 | Argon2id anahtar türetme |
| `pytest` 9.1 | Otomatik testler |
| JSON | Vault dosyası formatı |

---

## Uygulama Adımları

Simülatör aşağıdaki adımlarla çalıştırılıp gösterilmiştir:

1. Bağımlılıklar kurulur ve uygulama başlatılır: `pip install -r requirements.txt`, ardından `streamlit run app.py` (tarayıcıda `http://localhost:8501`).
2. **Başlık 1 — KDF Benchmark:** Ana parola girilir; dört konfigürasyon (PBKDF2 1.000 / 100.000 / 600.000 iterasyon ve Argon2id) için anahtar türetme süresi ölçülüp tablo ve grafikle karşılaştırılır.
3. **Başlık 2 — Kasa oluşturma:** Sahte bir kayıt (site, kullanıcı adı, parola, not) girilir, KDF (PBKDF2/Argon2id) seçilir ve kayıt hem güvensiz (AES-CTR) hem güvenli (AES-GCM) modda diske yazılır. Diske yazılan JSON, 12 baytlık nonce ve 16 baytlık GCM etiketiyle birlikte görüntülenir.
4. **Başlık 3 — Kurcalama senaryoları:** Her senaryoda kasa dosyası kasıtlı olarak bozulur ve iki modun tepkisi karşılaştırılır (bit çevirme, KDF düşürme, sürüm değişikliği, korumasız metadata, tam dosya replay).
5. **Başlık 4 — Özet:** Tüm özellikler için güvensiz/güvenli karşılaştırma tablosu sunulur.

Kripto davranışı ayrıca 21 otomatik test (`pytest`) ile doğrulanmıştır.

---

## Demo Senaryoları

1. **KDF kıyaslama:** Farklı PBKDF2 iterasyon sayıları ve Argon2id için türetme süresi ölçülür.
2. **Vault kaydetme:** Sahte bir kayıt hem güvensiz (AES-CTR) hem de güvenli (AES-GCM) modda şifrelenir.
3. **Bit çevirme saldırısı:** Güvensiz vault bozuk veri döndürür; güvenli vault reddeder.
4. **KDF düşürme saldırısı:** Güvensiz vault sessizce kabul eder; güvenli vault reddeder.
5. **Sürüm alanı (in-place) değişikliği:** Güvensiz vault sessizce kabul eder; güvenli vault sürümü AAD'ye bağladığı için reddeder.
6. **Tam dosya replay (rollback):** Eski ama geçerli biçimde şifrelenmiş bir vault dosyasının tamamıyla değiştirilmesi **her iki modda da başarıyla çözülür** — AAD bunu engellemez; gerçek replay koruması vault dosyasının dışında tutulan harici bir monoton sayaç gerektirir.
7. **Korumasız metadata değişikliği:** Her iki modda da geçer — yalnızca AAD'ye dahil edilen alanların korunduğunu gösterir.

---

## Sonuçlar (Ölçülen Gözlemler)

Apple M4 üzerinde elde edilen somut gözlemler:

- **KDF maliyeti:** PBKDF2 600.000 iterasyon (~113 ms), 1.000 iterasyona (~0,2 ms) kıyasla her brute-force denemesini yaklaşık 500× pahalı hale getirmiştir. Argon2id (~90 ms) benzer süreyi 64 MiB bellek gereksinimiyle birleştirir.
- **Bit çevirme (güvensiz):** Parolanın ilk harfine denk gelen tek bir şifreli bayt `0x20` maskesiyle çevrildiğinde, parola `SuperSecret!42` → `superSecret!42` olarak öngörülebilir biçimde değişmiş ve sistem hiçbir hata vermemiştir. Bu, AES-CTR'nin şekillendirilebilirliğini (malleability) doğrular.
- **Bit çevirme (güvenli):** Aynı değişiklik GCM kimlik doğrulama etiketini geçersiz kılmış ve `IntegrityError` ile reddedilmiştir.
- **KDF düşürme ve sürüm (in-place) değişikliği:** Güvensiz modda sessizce kabul edilmiş; güvenli modda, bu alanlar AAD'ye bağlı olduğu için reddedilmiştir.
- **Tam dosya replay:** Eski ama geçerli bir kasa dosyası her iki modda da başarıyla çözülmüş; AAD'nin bu saldırıyı engelleyemediği deneysel olarak gösterilmiştir.
- **Doğrulama:** Round-trip ve kurcalama davranışlarını kapsayan 21/21 `pytest` testi başarıyla geçmiştir.

---

## Güvenlik Sonucu

Bir parola yöneticisi yalnızca vault verilerini şifrelememeli; aynı zamanda şifreli metnin ve kriptografik parametrelerin bütünlüğünü de korumalıdır. Aksi hâlde saldırgan vault'u doğrudan okumak zorunda kalmadan sistemi zayıflatabilir veya manipüle edebilir. AEAD (AES-GCM gibi) ile birlikte vault sürümü ve KDF parametrelerinin AAD'ye bağlanması, bu tür saldırıları etkili biçimde engeller.
