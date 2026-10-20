# Third-party components

LANORA — Local Area Network Observation & Risk Assessment — includes the following third-party components.

| Component | Version | License | Use |
|---|---|---|---|
| .NET / ASP.NET Core / Windows Forms runtime | 10.0 | MIT | Application runtime (self-contained) |
| Microsoft.Data.Sqlite | 10.0.13 | MIT | Local database |
| SQLitePCLRaw (bundle_e_sqlite3, core, provider) | 2.1.13 | Apache-2.0 | SQLite native library |
| SQLite | e_sqlite3 | Public domain | Database engine |
| PDFsharp / MigraDoc (PDFsharp-MigraDoc) | 6.2.4 | MIT | PDF report (deliberately pinned because 6.3+ is AGPL) |
| System.Security.Cryptography.Pkcs | 10.0.13 | MIT | Transitive dependency of PDFsharp (patched version) |
| ClosedXML | 0.105.1 | MIT | XLSX report |
| ClosedXML.Parser | 2.0.0 | MIT | ClosedXML dependency |
| DocumentFormat.OpenXml | 3.1.1 | MIT | ClosedXML dependency |
| ExcelNumberFormat | 1.1.0 | MIT | ClosedXML dependency |
| RBush.Signed | 4.0.0 | MIT | ClosedXML dependency |
| SixLabors.Fonts | 1.0.0 | Apache-2.0 | ClosedXML dependency |
| IEEE OUI (MA-L) list | 2026-10-19 | Public list of the IEEE Registration Authority | Offline vendor lookup (`Resources/oui.tsv.gz`) |

The test project also uses xUnit (Apache-2.0), Microsoft.NET.Test.Sdk (MIT) and coverlet (MIT). These are not part of the distribution.

LANORA's advanced scan is a **fully built-in C# engine that needs no installation**. It uses only the standard networking APIs of the .NET runtime (System.Net.Sockets, System.Net.NetworkInformation.Ping, System.Net.Dns) and contains no additional third-party scanning component.
