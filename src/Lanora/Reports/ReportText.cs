namespace Lanora.Reports;

/// <summary>Report texts, ordered [en, tr, de]; English is the primary language. Technical codes are language-independent; raw banners are not translated.</summary>
public sealed class ReportText
{
    private static readonly Dictionary<string, string[]> M = new()
    {
        ["title"] = new[] { "Local network observation report", "Yerel ağ gözlem raporu", "Bericht zur lokalen Netzwerkbeobachtung" },
        ["state.completed"] = new[] { "Completed", "Tamamlandı", "Abgeschlossen" },
        ["state.partial"] = new[] { "Partial result", "Kısmi sonuç", "Teilergebnis" },
        ["state.cancelled"] = new[] { "Cancelled", "İptal edildi", "Abgebrochen" },
        ["state.failed"] = new[] { "Failed", "Hata", "Fehlgeschlagen" },
        ["state.interrupted"] = new[] { "Interrupted", "Yarıda kesildi", "Unterbrochen" },
        ["state.running"] = new[] { "In progress", "Devam ediyor", "Läuft" },
        ["state.queued"] = new[] { "Queued", "Sırada", "In Warteschlange" },
        ["state.cancelling"] = new[] { "Cancelling", "İptal ediliyor", "Wird abgebrochen" },
        ["summary"] = new[] { "Summary", "Özet", "Zusammenfassung" },
        ["devices"] = new[] { "Devices", "Cihazlar", "Geräte" },
        ["ports"] = new[] { "Ports", "Portlar", "Ports" },
        ["findings"] = new[] { "Findings", "Bulgular", "Hinweise" },
        ["comparison"] = new[] { "Comparison", "Karşılaştırma", "Vergleich" },
        ["network"] = new[] { "Network", "Ağ", "Netzwerk" },
        ["interface"] = new[] { "Adapter", "Bağdaştırıcı", "Adapter" },
        ["started"] = new[] { "Started", "Başlangıç", "Beginn" },
        ["ended"] = new[] { "Ended", "Bitiş", "Ende" },
        ["state"] = new[] { "State", "Durum", "Status" },
        ["reason"] = new[] { "Reason", "Neden", "Grund" },
        ["profile"] = new[] { "Profile", "Profil", "Profil" },
        ["profile.quick"] = new[] { "Quick TCP", "Hızlı TCP", "Schneller TCP-Scan" },
        ["profile.standard"] = new[] { "Standard TCP", "Standart TCP", "Standard TCP-Scan" },
        ["profile.custom"] = new[] { "Custom TCP", "Özel TCP", "Benutzerdefinierter TCP-Scan" },
        ["port_count"] = new[] { "Port count", "Port sayısı", "Anzahl Ports" },
        ["addresses_probed"] = new[] { "Addresses probed", "Yoklanan adres", "Geprüfte Adressen" },
        ["hosts_responded"] = new[] { "Responding devices", "Yanıt veren cihaz", "Antwortende Geräte" },
        ["unverified"] = new[] { "Unverified addresses", "Doğrulanamayan adres", "Nicht bestätigte Adressen" },
        ["score"] = new[] { "Network security indicator", "Ağ güvenlik göstergesi", "Netzwerksicherheitsanzeige" },
        ["score_basis"] = new[] { "Based on port observations within the scan scope.", "Tarama kapsamındaki port gözlemlerine dayanır.", "Basiert auf Portbeobachtungen im Scanumfang." },
        ["score_limit"] = new[] { "A high score does not mean that every security property of the device or network was verified. A local scan does not measure reachability from the WAN.", "Yüksek puan, cihazın veya ağın tüm güvenlik özelliklerinin doğrulandığı anlamına gelmez. Yerel tarama WAN tarafından erişilebilirliği ölçmez.", "Ein hoher Wert bedeutet nicht, dass alle Sicherheitseigenschaften von Gerät oder Netzwerk geprüft wurden. Ein lokaler Scan misst keine Erreichbarkeit aus dem WAN." },
        ["coverage"] = new[] { "Measurement coverage", "Ölçüm kapsamı", "Messabdeckung" },
        ["coverage_note"] = new[] { "{0} of {1} device-port pairs produced a definite result (open or closed). This does not mean every device on the network was found.", "{0} / {1} cihaz-port çifti kesin sonuç (açık veya kapalı) üretti. Bu oran ağdaki tüm cihazların bulunduğu anlamına gelmez.", "{0} von {1} Geräte-Port-Paaren ergaben ein eindeutiges Ergebnis (offen oder geschlossen). Das bedeutet nicht, dass alle Geräte gefunden wurden." },
        ["not_evaluable"] = new[] { "Not evaluable", "Değerlendirilemedi", "Nicht bewertbar" },
        ["insufficient_coverage"] = new[] { "Insufficient coverage", "Yetersiz kapsam", "Unzureichende Abdeckung" },
        ["provisional"] = new[] { "Provisional", "Ön sonuç", "Vorläufig" },
        ["engine"] = new[] { "Engine version", "Motor sürümü", "Engine-Version" },
        ["ruleset"] = new[] { "Ruleset version", "Kural sürümü", "Regelversion" },
        ["port_list"] = new[] { "Port list version", "Port listesi sürümü", "Portlisten-Version" },
        ["state_chart"] = new[] { "Port state distribution", "Port durumu dağılımı", "Verteilung der Portzustände" },
        ["count"] = new[] { "Count", "Adet", "Anzahl" },
        ["device"] = new[] { "Device", "Cihaz", "Gerät" },
        ["ip"] = new[] { "IP address", "IP adresi", "IP-Adresse" },
        ["mac"] = new[] { "MAC address", "MAC adresi", "MAC-Adresse" },
        ["vendor"] = new[] { "Manufacturer", "Üretici", "Hersteller" },
        ["os"] = new[] { "Operating system (estimate)", "İşletim sistemi (tahmin)", "Betriebssystem (Schätzung)" },
        ["device_score"] = new[] { "Device indicator", "Cihaz göstergesi", "Geräteanzeige" },
        ["open_ports"] = new[] { "Open ports", "Açık portlar", "Offene Ports" },
        ["discovery"] = new[] { "Discovery evidence", "Keşif kanıtı", "Erkennungsnachweis" },
        ["identity"] = new[] { "Identity match", "Kimlik eşleşmesi", "Identitätszuordnung" },
        ["protocol"] = new[] { "Protocol", "Protokol", "Protokoll" },
        ["port"] = new[] { "Port", "Port", "Port" },
        ["state_code"] = new[] { "State code", "Durum kodu", "Statuscode" },
        ["reason_code"] = new[] { "Reason code", "Neden kodu", "Grundcode" },
        ["method"] = new[] { "Method", "Yöntem", "Methode" },
        ["service"] = new[] { "Service (estimate)", "Servis (tahmin)", "Dienst (Schätzung)" },
        ["service_method"] = new[] { "Service evidence method", "Servis kanıt yöntemi", "Nachweismethode" },
        ["product"] = new[] { "Product", "Ürün", "Produkt" },
        ["version"] = new[] { "Version", "Sürüm", "Version" },
        ["evidence"] = new[] { "Evidence", "Kanıt", "Nachweis" },
        ["observed_at"] = new[] { "Observed at", "Gözlem zamanı", "Beobachtet am" },
        ["rule"] = new[] { "Rule", "Kural", "Regel" },
        ["severity"] = new[] { "Priority", "Öncelik", "Priorität" },
        ["penalty"] = new[] { "Penalty", "Ceza", "Abzug" },
        ["what_observed"] = new[] { "What we observed", "Neyi gözledik", "Was wir beobachtet haben" },
        ["what_means"] = new[] { "What it means", "Ne anlama geliyor", "Was es bedeutet" },
        ["what_do"] = new[] { "What I can do", "Ne yapabilirim", "Was ich tun kann" },
        ["how_verify"] = new[] { "How to verify", "Nasıl doğrularım", "Wie ich es prüfe" },
        ["required_note"] = new[] { "User marked this service as required (does not change the score).", "Kullanıcı bu servisi gerekli olarak işaretledi (puanı değiştirmez).", "Der Benutzer hat diesen Dienst als benötigt markiert (ändert den Wert nicht)." },
        ["sev.high"] = new[] { "High", "Yüksek", "Hoch" },
        ["sev.medium"] = new[] { "Medium", "Orta", "Mittel" },
        ["sev.info"] = new[] { "Informational", "Bilgilendirme", "Information" },
        ["st.open"] = new[] { "Open", "Açık", "Offen" },
        ["st.closed"] = new[] { "Closed", "Kapalı", "Geschlossen" },
        ["st.filtered"] = new[] { "Possibly filtered", "Filtrelenmiş olabilir", "Möglicherweise gefiltert" },
        ["st.no_response"] = new[] { "No response", "Yanıt alınamadı", "Keine Antwort" },
        ["st.open_filtered"] = new[] { "Open or filtered", "Açık veya filtrelenmiş", "Offen oder gefiltert" },
        ["st.not_tested"] = new[] { "Not tested", "Test edilmedi", "Nicht getestet" },
        ["st.error"] = new[] { "Measurement error", "Ölçüm hatası", "Messfehler" },
        ["missing"] = new[] { "Missing fields", "Eksik alanlar", "Fehlende Felder" },
        ["missing_mac"] = new[] { "MAC address not available (routed network or no neighbor table entry).", "MAC adresi alınamadı (yönlendirilmiş ağ veya komşu tablosunda kayıt yok).", "MAC-Adresse nicht verfügbar (geroutetes Netz oder kein Nachbareintrag)." },
        ["unknown"] = new[] { "Unknown", "Bilinmiyor", "Unbekannt" },
        ["random_mac"] = new[] { "Random/local MAC – manufacturer cannot be determined", "Rastgele/yerel MAC – üretici belirlenemez", "Zufällige/lokale MAC – Hersteller nicht bestimmbar" },
        ["partial_note"] = new[] { "This scan did not complete. Unmeasured ports are listed as 'Not tested' and the score is provisional.", "Bu tarama tamamlanmadı. Ölçülmeyen portlar 'Test edilmedi' olarak listelenir ve puan ön sonuçtur.", "Dieser Scan wurde nicht abgeschlossen. Nicht gemessene Ports sind als 'Nicht getestet' aufgeführt und der Wert ist vorläufig." },
        ["running_note"] = new[] { "Snapshot time: {0}. The job is still running; the report only contains saved data.", "Snapshot zamanı: {0}. İş devam ediyor; rapor yalnızca kaydedilmiş verileri içerir.", "Snapshot-Zeit: {0}. Der Auftrag läuft noch; der Bericht enthält nur gespeicherte Daten." },
        ["no_devices"] = new[] { "No responding devices were found in this scan.", "Bu taramada yanıt veren cihaz bulunamadı.", "In diesem Scan wurden keine antwortenden Geräte gefunden." },
        ["no_findings"] = new[] { "No priority findings observed. This applies only to the selected ports.", "Öncelikli bulgu gözlenmedi. Bu, yalnızca seçilen portlar için geçerlidir.", "Keine prioritären Hinweise beobachtet. Das gilt nur für die ausgewählten Ports." },
        ["this_computer"] = new[] { "This computer", "Bu bilgisayar", "Dieser Computer" },
        ["gateway"] = new[] { "Gateway", "Ağ geçidi", "Gateway" },
        ["generated"] = new[] { "Generated", "Oluşturulma", "Erstellt" },
        ["page"] = new[] { "Page", "Sayfa", "Seite" },
        ["compare_with"] = new[] { "Compared previous scan", "Karşılaştırılan önceki tarama", "Verglichener früherer Scan" },
        ["compare_none"] = new[] { "No comparable previous scan.", "Karşılaştırılabilir önceki tarama yok.", "Kein vergleichbarer früherer Scan." },
        ["compare_incompatible"] = new[] { "Scope differs ({0}); score changes must not be read as equivalent changes.", "Kapsam farklı ({0}); skor değişimi eşdeğer değişim olarak yorumlanmamalıdır.", "Umfang unterscheidet sich ({0}); Wertänderungen sind nicht gleichwertig." },
        ["change"] = new[] { "Change", "Değişim", "Änderung" },
        ["newly_opened"] = new[] { "Newly opened", "Yeni açılan", "Neu geöffnet" },
        ["closed_evidence"] = new[] { "Closed (closed evidence)", "Kapandı (kapalı kanıtı)", "Geschlossen (Nachweis)" },
        ["no_longer"] = new[] { "No longer responding", "Artık yanıt yok", "Keine Antwort mehr" },
        ["not_measured"] = new[] { "Not measured", "Ölçülmedi", "Nicht gemessen" },
        ["before"] = new[] { "Before", "Önce", "Vorher" },
        ["after"] = new[] { "After", "Sonra", "Nachher" },
        ["field"] = new[] { "Field", "Alan", "Feld" },
        ["value"] = new[] { "Value", "Değer", "Wert" },
        ["code"] = new[] { "Code", "Kod", "Code" },
        ["description"] = new[] { "Description", "Açıklama", "Beschreibung" },
        ["yes"] = new[] { "Yes", "Evet", "Ja" },
        ["no"] = new[] { "No", "Hayır", "Nein" },
        ["conf.high"] = new[] { "high confidence", "yüksek güven", "hohes Vertrauen" },
        ["conf.medium"] = new[] { "medium confidence", "orta güven", "mittleres Vertrauen" },
        ["conf.low"] = new[] { "low confidence", "düşük güven", "geringes Vertrauen" },
        ["src.local_system"] = new[] { "local system", "yerel sistem", "lokales System" },
        ["src.icmp_ttl"] = new[] { "ICMP TTL", "ICMP TTL", "ICMP-TTL" },
        ["src.port_pattern"] = new[] { "port pattern", "port deseni", "Portmuster" },
        ["src.ssh_banner"] = new[] { "SSH banner", "SSH karşılaması", "SSH-Banner" },
        ["downloaded_note"] = new[] { "This report was generated locally; no scan data was sent to the internet.", "Bu rapor yerel olarak üretildi; tarama verisi internete gönderilmedi.", "Dieser Bericht wurde lokal erstellt; es wurden keine Scandaten ins Internet gesendet." },
        ["hostname"] = new[] { "Hostname", "Cihaz adı", "Hostname" },
        ["engine_mode"] = new[] { "Scan engine", "Tarama motoru", "Scan-Engine" },
        ["advanced_engine"] = new[] { "Advanced scan", "Gelişmiş tarama", "Erweiterter Scan" },
        ["external_note"] = new[] { "This scan includes external/hostname targets and was run under the user's authorization statement.", "Bu tarama yerel ağ dışı/hostname hedefleri içerir ve kullanıcı yetki beyanıyla yürütülmüştür.", "Dieser Scan enthält externe/Hostname-Ziele und wurde mit Nutzerfreigabe ausgeführt." },
        ["scripts"] = new[] { "Script results (NSE)", "Betik sonuçları (NSE)", "Skriptergebnisse (NSE)" },
        ["traceroute"] = new[] { "Traceroute", "Traceroute", "Traceroute" },
    };

    public ReportText(string lang)
    {
        Lang = lang is "tr" or "de" ? lang : "en";
        Index = Lang switch { "tr" => 1, "de" => 2, _ => 0 };
        Culture = new System.Globalization.CultureInfo(Lang switch { "tr" => "tr-TR", "de" => "de-DE", _ => "en-GB" });
    }

    public string Lang { get; }
    public int Index { get; }
    public System.Globalization.CultureInfo Culture { get; }

    public string this[string key] => M.TryGetValue(key, out var v) ? v[Index] : key;

    public string F(string key, params object[] args) => string.Format(Culture, this[key], args);

    public string State(string code) => M.ContainsKey("st." + code) ? this["st." + code] : code;
    public string ScanState(string code) => M.ContainsKey("state." + code) ? this["state." + code] : code;
    public string Severity(string code) => this["sev." + code];
    public string OsSource(string? code) =>
        code is null ? "" : string.Join(" + ", code.Split('+').Select(p => M.ContainsKey("src." + p) ? this["src." + p] : p));

    public string Profile(string code) => M.ContainsKey("profile." + code) ? this["profile." + code] : code;

    public string Date(string iso) => Infrastructure.Clock.Parse(iso).ToLocalTime().ToString("g", Culture);
}
