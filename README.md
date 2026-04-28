# STIG Helper v1.4.1

STIG Helper is a Windows-friendly desktop toolkit for working with DISA STIG checklists.
It is designed to help analysts merge, compare, export, summarize, and document STIG results
without requiring extra third-party installs or heavy command-line use.

## What It Does

STIG Helper currently supports these main workflows:

### 1. CKL Merger
- Merges an ACAS checklist and an Evaluate-STIG checklist for the same system
- Preserves and combines checklist data using the app's merge rules
- Writes merged checklist output into the `Merged` folder

#### Merge Rules
- ACAS is the base checklist structure
- Eval-STIG wins for asset metadata when Eval-STIG has a populated value
- For matching V-IDs, status precedence is:
  - `Not_Applicable`
  - `NotAFinding`
  - `Open`
  - `Not_Reviewed`
- The higher-priority status wins
- If both scanners have the same status priority, ACAS wins the tie
- If ACAS already says `NotAFinding` or `Not_Applicable`, keep ACAS as the base even when Eval-STIG is less favorable
- `FINDING_DETAILS` and `COMMENTS` are combined from both sources
- If one scanner says `Open` and the other says `NotAFinding` or `Not_Applicable`, the merged comments include a `[MERGE NOTE]`
- V-IDs found only in Eval-STIG are appended into the merged checklist
- V-IDs found only in ACAS remain in place
- If Eval-STIG has the newer STIG benchmark/version label, the merged checklist uses Eval-STIG's `STIG_INFO`

### 2. CKL Diff
- Compares before/after checklist snapshots
- Highlights status changes, regressions, improvements, and drift
- Produces HTML diff reports

### 3. Create Status Report
- Generates checklist summary reports from a `CKL` or `CKLB`
- Supports:
  - `HTML`
  - `XLSX`
  - `Both`
- Includes:
  - Open CAT I
  - Not Reviewed CAT I
  - Open CAT IIs
  - Not Reviewed CAT IIs
  - Open CAT IIIs
  - Not Reviewed CAT IIIs
  - Not a Finding
  - Not Applicable
  - Total
- Also includes detailed finding rows

### 4. Create Artifact Report
- Generates a Word `.docx` artifact report from a `CKL` or `CKLB`
- Lets the user:
  - choose one or more V-IDs
  - review/edit artifact narrative text
  - export a Word document
- Each artifact section includes:
  - V-ID
  - Rule title
  - Status
  - Narrative text
  - Screenshot placeholder

### 5. Standardize / Export Checklist
- Standardizes checklist filenames and exports between supported formats
- `CKL -> CKL` is primarily used to create a clean, consistently named export copy
- When standardizing a checklist, the exported filename keeps the checklist's original date when it can be detected from the filename or file metadata
- Supported outputs:
  - `CKL`
  - `CKLB`

### 6. STIG History
- Saves checklist snapshots into tracked history buckets
- Helps maintain consistent naming for repeated assessments
- Supports duplicate detection and bucket metadata
- Includes history summary exports

## Supported Formats

- `CKL`
- `CKLB`
- `HTML`
- `XLSX`
- `DOCX`

## Naming Convention Support

STIG Helper includes an automatic naming assistant to help keep checklist and export names
consistent.

The naming assistant can:
- default the `Zone` field to `Production`
- let the user choose one of the supported zones:
  - `Production`
  - `Omaha`
  - `ZoneB`
- let the user fill in `Project Name`
- read `HOST_IP` when present and mask the first two octets as `x.x.`
- fall back to `HOST_NAME`, `HOST_FQDN`, or the source filename when needed
- suggest `OS / Product`
- suggest a subcategory or app name when applicable
- build a recommended name such as:
  - `Production_AMCAP_RGBSI_x.x.68.25`
  - `Production_AMCAP_RGBSI_x.x.68.25_Edge`
  - `Production_AMCAP_RGBSI_x.x.68.25_IIS Site`
  - `Production_AMCAP_RGBSI_x.x.68.25_App Server SRG_Traksys`

The user can still change the suggested name, but the recommended name is intended to keep
history and exports more consistent.

Example:
- `10.60.68.25` becomes `x.x.68.25`
- `10.60.68.25.edge.ckl` can standardize to `Production_Project_x.x.68.25_Edge`
- OS checklists do not add a subcategory suffix after the masked IP

## Default Folders

The included `setup.bat` creates the default working folders:

- `CKLs`
- `Reports`
- `Snapshots`
- `Merged`
- `Exports`

## Installation

Recommended location:

- `%USERPROFILE%\Documents`

Recommended extraction result:

- `%USERPROFILE%\Documents\STIG_Helper`

Notes:

- The release zip should be extracted before running the app
- A plain `.zip` file cannot force Windows to choose `%USERPROFILE%\Documents`
- The zip can, however, include a fixed top-level folder so extracting into `Documents` creates the same `STIG_Helper` folder every time
- A companion `unpack.bat` can automate extraction into `%USERPROFILE%\Documents`
- Release zip files should use a versioned name such as `STIG_Helper_package_v1.1.1.zip`
- `unpack.bat` looks for the highest available versioned STIG Helper zip next to itself and uses that package automatically

## Main Files

- [stig_helper.py](C:\Users\ychoo\projects\STIG_HELPER\stig_helper.py)
  Main GUI launcher
- [combine_stig.py](C:\Users\ychoo\projects\STIG_HELPER\combine_stig.py)
  Merge engine, report generation, export logic, and artifact document generation
- [stig_diff.py](C:\Users\ychoo\projects\STIG_HELPER\stig_diff.py)
  Snapshot history and diff engine
- [main.bat](C:\Users\ychoo\projects\STIG_HELPER\main.bat)
  Main Windows launcher
- [setup.bat](C:\Users\ychoo\projects\STIG_HELPER\setup.bat)
  First-run setup helper

## How To Start

1. Either run `unpack.bat`, or extract the release zip into `%USERPROFILE%\Documents`.
2. If you use `unpack.bat`, it will automatically run [setup.bat](C:\Users\ychoo\projects\STIG_HELPER\setup.bat) after extraction.
3. Launch the app with [main.bat](C:\Users\ychoo\projects\STIG_HELPER\main.bat).
4. Choose the workflow you want from the main menu.

## Notes

- Merged checklists are saved in `Merged`
- Reports are saved in `Reports`
- Exported checklists are saved in `Exports`
- History snapshots are saved in `Snapshots`

## Feedback / Questions

For questions, comments, or improvement requests:

- Young Choo
- Lead Technical Engineer
- Defense, Intel & Health BU | Enterprise Solutions SL
- young.gyu.choo@ecstech.com
