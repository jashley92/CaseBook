# Third-Party Notices

CaseBook bundles and depends on the following third-party components.
Each is used under its respective open-source license, reproduced or linked below.

## Vendored (redistributed) assets

| Component | Version | License | Location |
|-----------|---------|---------|----------|
| [Bootstrap](https://github.com/twbs/bootstrap) (CSS) | 5.3.3 | MIT | `src/IncidentManager.Web/wwwroot/bootstrap/` |
| [vis-network](https://github.com/visjs/vis-network) | 9.1.9 | Apache-2.0 / MIT (dual) | `src/IncidentManager.Web/wwwroot/lib/vis-network/` |
| [Bootstrap Icons](https://github.com/twbs/icons) | 1.11.3 | MIT | `src/IncidentManager.Web/wwwroot/lib/bootstrap-icons/` |
| [EasyMDE](https://github.com/Ionaru/easy-markdown-editor) | 2.18.0 | MIT | `src/IncidentManager.Web/wwwroot/lib/easymde/` |
| [docx-preview](https://github.com/VolodymyrBaydalka/docxjs) | 0.4.1 | Apache-2.0 | `src/IncidentManager.Web/wwwroot/lib/docx-preview/` |
| [JSZip](https://github.com/Stuk/jszip) | 3.10.2 | MIT (dual MIT / GPL-3.0; used under MIT) | `src/IncidentManager.Web/wwwroot/lib/docx-preview/` |
| [DejaVu Sans](https://dejavu-fonts.github.io/) | 2.37 | Bitstream Vera / Arev (permissive, redistributable) | `src/IncidentManager.Infrastructure/Reporting/Fonts/` |

DejaVu Sans faces (Regular/Bold/Oblique/BoldOblique) are embedded in the Infrastructure
assembly (`Reporting/EmbeddedFonts.cs`) so the diagrams drawn into Word reports render the same on
any host, independent of installed fonts. Full license text: `Reporting/Fonts/LICENSE-DejaVu.txt`.

vis-network is dual-licensed under Apache License 2.0 and MIT; it is redistributed
here in minified form (`vis-network.min.js`, `vis-network.min.css`) to power the
entity-relationship graph. See the visjs project for full license text.

docx-preview (with its dependency JSZip) is redistributed in minified form to show a filled
Word template in the case Report tab's preview, in the browser. It loads only on that tab.

## NuGet dependencies

| Package | Version | License |
|---------|---------|---------|
| DocumentFormat.OpenXml | 3.5.1 | MIT |
| Markdig | 1.3.2 | BSD-2-Clause |
| FluentValidation | 12.1.1 | Apache-2.0 |
| SkiaSharp (+ SkiaSharp.NativeAssets.Linux.NoDependencies) | 4.152.1 | MIT |
| Microsoft.AspNetCore.Authentication.Negotiate | 10.x | MIT |
| System.DirectoryServices.AccountManagement | 10.x | MIT |
| Microsoft.EntityFrameworkCore (+ Relational, Sqlite, SqlServer, Design) | 10.x | MIT |
| Microsoft.Extensions.* (Configuration, DI, Options) | 10.x | MIT |

Microsoft packages are © Microsoft Corporation, licensed under the MIT License.
Full license texts are available in each package (NuGet) or the linked project
repositories.

## Test-only dependencies (not redistributed)

| Package | Version | License |
|---------|---------|---------|
| xunit, xunit.runner.visualstudio | 2.9.3, 2.8.2 | Apache-2.0 |
| Microsoft.NET.Test.Sdk, Microsoft.AspNetCore.Mvc.Testing | 17.14.1, 10.x | MIT |
| coverlet.collector | 6.0.4 | MIT |
| FluentAssertions | 8.10.0 | Xceed Community License (free for non-commercial use; commercial use requires a paid license) |
