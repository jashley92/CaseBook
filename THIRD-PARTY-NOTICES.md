# Third-Party Notices

CaseBook bundles and depends on the following third-party components.
Each is used under its respective open-source license, reproduced or linked below.

## Vendored (redistributed) assets

| Component | Version | License | Location |
|-----------|---------|---------|----------|
| [vis-network](https://github.com/visjs/vis-network) | 9.1.9 | Apache-2.0 / MIT (dual) | `src/IncidentManager.Web/wwwroot/lib/vis-network/` |
| [Bootstrap Icons](https://github.com/twbs/icons) | 1.11.3 | MIT | `src/IncidentManager.Web/wwwroot/lib/bootstrap-icons/` |
| [EasyMDE](https://github.com/Ionaru/easy-markdown-editor) | 2.18.0 | MIT | `src/IncidentManager.Web/wwwroot/lib/easymde/` |
| [DejaVu Sans](https://dejavu-fonts.github.io/) | 2.37 | Bitstream Vera / Arev (permissive, redistributable) | `src/IncidentManager.Infrastructure/Reporting/Fonts/` |

DejaVu Sans faces (Regular/Bold/Oblique/BoldOblique) are embedded in the Infrastructure
assembly and served by `EmbeddedFontResolver` so PDF report generation is self-contained and
independent of host-installed fonts. Full license text: `Reporting/Fonts/LICENSE-DejaVu.txt`.

vis-network is dual-licensed under Apache License 2.0 and MIT; it is redistributed
here in minified form (`vis-network.min.js`, `vis-network.min.css`) to power the
entity-relationship graph. See the visjs project for full license text.

## NuGet dependencies

| Package | Version | License |
|---------|---------|---------|
| DocumentFormat.OpenXml | 3.5.1 | MIT |
| Markdig | 1.3.2 | BSD-2-Clause |
| PDFsharp-MigraDoc | 6.2.4 | MIT |
| FluentValidation | 12.1.1 | Apache-2.0 |
| Microsoft.AspNetCore.Authentication.Negotiate | 8.x | MIT |
| Microsoft.EntityFrameworkCore (+ Relational, Sqlite, SqlServer, Design) | 8.x | MIT |
| Microsoft.Extensions.* (Configuration, DI, Options) | 8.x | MIT |

Microsoft packages are © Microsoft Corporation, licensed under the MIT License.
Full license texts are available in each package (NuGet) or the linked project
repositories.
