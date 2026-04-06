# Nobl9 Account Analyzer

A comprehensive Python tool for analyzing Nobl9 SLO organizations, providing detailed insights into project health, SLO coverage, alert policy effectiveness, and resource utilization.

## Overview

The Nobl9 Account Analyzer is designed to help organizations understand and optimize their SLO implementation across projects. It provides actionable insights through detailed analysis of projects, SLOs, alert policies, services, and user activity patterns.

### Scripts in this Repository

- **`account_analyzer.py`**: Comprehensive account-wide analysis with multiple export formats
- **`slo_analysis.py`**: Specialized SLO analysis with user information resolution and service details
- **`composite_analyzer.py`**: Focused analysis of composite SLOs and their components
- **`data_source_analyzer.py`**: Data source utilization and configuration analysis
- **`slo_creation_report.py`**: Track SLO creation activity over configurable time periods
- **`error_budget_report.py`**: Analyze error budget consumption and identify SLOs with high burn rates

## Features

### Core Analysis
- **Project Analysis**: Comprehensive overview of all projects with SLO, service, and alert policy counts
- **SLO Coverage Analysis**: Identifies SLOs with and without alert policies
- **Alert Policy Effectiveness**: Analyzes policy usage and identifies unused policies
- **Service Analysis**: Service-level SLO distribution and coverage metrics
- **Data Source Analysis**: Breakdown of monitoring tools and data source utilization

### Advanced Analytics
- **Time Window Analysis**: Time window distribution patterns and rolling vs calendar-aligned windows
- **Recent Changes Tracking**: Most recently updated SLOs with timestamps
- **Audit Trail Analysis**: User activity patterns and change breakdowns
- **Resource Utilization**: Official usage metrics from Nobl9 Reports API (SLO Units, Users, Data Sources)

### Export Capabilities
- **Console Output**: Formatted, colorized terminal display
- **CSV Export**: Structured data for spreadsheet analysis
- **JSON Export**: Machine-readable format for integration
- **Excel Export**: Multi-tab spreadsheet with comprehensive data sets

## Prerequisites

### Required Dependencies
```bash
pip install requests colorama toml pandas openpyxl
```

### Nobl9 Configuration
- Valid Nobl9 account with API access
- Configured `sloctl` CLI tool
- Authentication credentials in `config.toml`

## Installation

1. Clone or download the script:
```bash
git clone https://github.com/jcoope02/nobl9-account-analyzer.git
cd nobl9-account-analyzer
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure `sloctl` is installed and configured:
```bash
sloctl config view
```

### Windows Setup

**Install Dependencies:**
```cmd
# Using Command Prompt or PowerShell
pip install -r requirements.txt
```

**Nobl9 CLI Setup:**
- Download `sloctl` for Windows from Nobl9 documentation
- Add `sloctl` to your system PATH
- Configure with: `sloctl config view`

**Windows Configuration Path:**
- Configuration file location: `%LOCALAPPDATA%\nobl9\config.toml`
- Example: `C:\Users\username\AppData\Local\nobl9\config.toml`

**Running on Windows:**
```cmd
# PowerShell or Command Prompt
python account_analyzer.py
python account_analyzer.py --format excel
python account_analyzer.py --audit-days 30
```

**Windows Terminal Recommendations:**
- Use Windows Terminal for best color support
- PowerShell 5.1+ or PowerShell Core recommended
- Command Prompt also supported

## Configuration

The tool uses your existing `sloctl` configuration. Ensure your `config.toml` file is properly configured with:

- Client ID and Client Secret
- Organization ID
- Context definitions for different environments

Default configuration locations:
- **macOS/Linux**: `~/.config/nobl9/config.toml`
- **Windows**: `%LOCALAPPDATA%\nobl9\config.toml`

## Usage

### Basic Usage

Run with default console output:
```bash
python3 account_analyzer.py
```

### Export Options

Generate CSV report:
```bash
python3 account_analyzer.py --format csv
```

Generate Excel report:
```bash
python3 account_analyzer.py --format excel
```

Generate JSON report:
```bash
python3 account_analyzer.py --format json
```

### Advanced Options

Collect extended audit data:
```bash
python3 account_analyzer.py --audit-days 30
```

### Interactive Mode

When run without export parameters, the tool offers an interactive export menu at completion.

### SLO Analysis Script

The `slo_analysis.py` script provides specialized SLO analysis with enhanced user information:

```bash
python3 slo_analysis.py --context <context_name>
```

**Features:**
- Resolves user IDs to names and emails for SLO creators
- Shows responsible users for each service
- Includes SLO counts per service
- Hyperlinks to SLOs and services in Nobl9 UI
- Supports custom instances (us1, cg1, etc.)

**Excel Export Includes:**
- **SLOs Sheet**: Complete SLO information with creator and responsible user details
- **Services Sheet**: Service information with SLO counts and responsible users
- Hidden technical columns (queries, targets, etc.) for cleaner viewing

## Report Sections

### Executive Summary
- Total counts for projects, SLOs, services, alert policies
- Official usage metrics from Nobl9 API
- SLO coverage percentage
- Recent activity summary

### Project Matrix
- Project-by-project breakdown of resources
- Projects without services or SLOs
- Resource distribution analysis

### Alert Coverage Analysis
- SLOs with and without alert policies
- Detailed list of uncovered SLOs (limited to 25 in console)
- Coverage percentage calculations

### Alert Policy Effectiveness
- Most used alert policies
- Unused alert policies (limited to 25 in console)
- Policy utilization metrics

### Service Analysis
- Top services by SLO count
- Services without SLOs
- Service coverage patterns

### Data Source Analysis
- Configured vs. used data sources
- Data source types and utilization
- Agent and Direct integration status

### SLO Objective Analysis
- Target value statistics
- Time window distribution
- Rolling vs. calendar-aligned windows

### Recent Changes
- 20 most recently updated SLOs
- Change timestamps and project information
- Activity tracking

### Audit Trail Summary
- User activity rankings
- Event type breakdowns
- Change pattern analysis

## Output Files

Generated files follow the naming convention:
```
nobl9_account_analysis_{context}_{timestamp}.{extension}
```

Examples:
- `nobl9_account_analysis_production_20240821_143052.xlsx`
- `nobl9_account_analysis_staging_20240821_143052.csv`

## Excel Export Structure

The Excel export includes multiple sheets:
- **Summary**: Executive summary metrics
- **Projects**: Complete project listing
- **SLOs**: Detailed SLO information with queries and hyperlinks
- **Composite SLOs**: Composite SLO details and components
- **Alert Policies**: Policy details and usage
- **Services**: Service information and SLO counts
- **SLOs without Alert Policies**: Uncovered SLOs
- **Unused Alert Policies**: Policies not attached to SLOs
- **Top Services by SLO Count**: Service rankings
- **Data Source Analysis**: Data source utilization
- **Time Window Analysis**: Time window patterns
- **Recent SLO Changes**: Recently modified SLOs
- **Recently Created SLOs**: Most recently created SLOs with creator information
- **Top 10 Most Active Users**: User activity rankings
- **User Activity**: Detailed user statistics
- **Event Types**: Audit event breakdowns

### SLOs Sheet Features

The SLOs sheet includes:
- **Display Name**: Clickable hyperlinks to open SLOs in Nobl9 UI
- **Query Columns**: 
  - **Query**: For rawMetric and thresholdMetric SLOs (single query)
  - **Numerator Query**: For ratioMetric and countMetrics (good events)
  - **Denominator Query**: For ratioMetric and countMetrics (total events)

## Authentication

The tool supports multiple authentication methods:
1. Context selection from `sloctl` configuration
2. Custom instance URLs for enterprise deployments
3. Automatic organization ID detection from JWT tokens
4. Environment variable fallbacks

## Error Handling

The tool includes comprehensive error handling for:
- Authentication failures
- Network connectivity issues
- API rate limiting
- Missing configuration files
- Data parsing errors

## Performance Considerations

The tool is optimized for efficiency:
- Single-pass data processing algorithms
- Efficient dictionary lookups (O(1) complexity)
- Memory-efficient generator expressions
- Minimal API calls with proper pagination

## Limitations

- Audit log analysis requires appropriate permissions (403 errors are handled gracefully)
- Some features may be limited in trial accounts
- Large organizations may experience longer processing times
- Custom instance configurations are now fully supported with automatic URL detection

## Troubleshooting

### Common Issues

**Authentication Errors**:
- Verify `sloctl` configuration
- Check client credentials
- Confirm organization access

**Missing Data**:
- Ensure proper permissions for all resource types
- Verify context selection
- Check network connectivity

**Export Failures**:
- Confirm pandas and openpyxl installation
- Verify write permissions in output directory
- Check available disk space

### Windows-Specific Issues

**Configuration File Not Found**:
- Check path: `%LOCALAPPDATA%\nobl9\config.toml`
- Verify sloctl is properly installed for Windows
- Run `sloctl config view` to verify setup

**Color Display Issues**:
- Install colorama: `pip install colorama`
- Use Windows Terminal for best color support
- Some older terminals may not display colors properly

**Permission Errors**:
- Run PowerShell/Command Prompt as Administrator if needed
- Check antivirus software blocking file creation
- Verify output directory write permissions

## Support

For issues related to:
- **Nobl9 Platform**: Contact Nobl9 support
- **Script Functionality**: Check error messages and logs
- **Configuration**: Refer to `sloctl` documentation

## License

This tool is provided as-is for analysis purposes. Ensure compliance with your organization's security and data handling policies.

## Recent Improvements

### v1.5 - Enhanced SLO Export and Query Support
- **SLO Query Extraction**: Added query columns to SLOs sheet showing actual queries for all metric types
- **Hyperlinked SLO Names**: Display Name column contains clickable links to open SLOs in Nobl9 UI
- **Improved SLO Tab Structure**: One row per SLO with alert policies as comma-separated list
- **Composite SLO Separation**: Composite SLOs excluded from regular SLOs tab (appear only in Composite SLOs sheet)
- **Query Support**: Handles rawMetric, ratioMetric, countMetrics, and thresholdMetric queries
- **Code Quality**: Refactored query extraction with proper type hints and documentation

### v1.4 - Enhanced Reliability and Accuracy
- **Fixed SLO Units Display**: Corrected API URL path to properly retrieve usage metrics
- **Improved Data Source Counting**: Fixed calculation to show unique data sources instead of SLO count
- **Enhanced Custom Instance Support**: Robust URL handling for non-standard Nobl9 deployments
- **Better Error Messages**: Clearer audit log collection status and API error reporting
- **Consistent Terminology**: Standardized "Alert Coverage" across all export formats
- **Cleaner Output**: Removed unnecessary target value statistics from time window analysis

### Key Fixes
- ✅ **SLO Queries**: All SLO queries now extracted and displayed in Excel export
- ✅ **Hyperlinks**: Direct links to SLOs in Nobl9 UI from Excel spreadsheet
- ✅ **SLO Deduplication**: Fixed issue where SLOs appeared multiple times in export
- ✅ **Composite SLOs**: Properly separated from regular SLOs in export
- ✅ **SLO Units**: Now correctly displays actual billing units (e.g., 255 instead of 0)
- ✅ **Custom URLs**: Handles various base URL formats for enterprise deployments
- ✅ **Error Clarity**: Clear success/failure messages for audit log collection
- ✅ **Export Consistency**: "Alert Coverage" terminology updated

---

## Error Budget Burn Report

**Script:** `error_budget_report.py`

Analyzes SLO error budget consumption over configurable time periods to identify SLOs with high error budget burn.

### Features
- **Time Period Selection**: 24 hours, 7 days, 14 days, or 28 days
- **Custom Threshold**: Set minimum budget drop percentage (default: 10%)
- **Status API Integration**: Fetches real-time error budget data from Nobl9 Status API v2
- **Severity Classification**: CRITICAL (≥50% burn), WARNING (≥25%), NOTICE (<25%)
- **Comprehensive Statistics**: Average burn, max burn, burn rates
- **Export Options**: Excel with hyperlinks or CSV format

### Usage
```bash
python3 error_budget_report.py
python3 error_budget_report.py --context ticketmaster
python3 error_budget_report.py --csv
```

### Excel Export Columns
- SLO Name, Display Name (hyperlinked), Severity
- Project, Service, Type
- Budget Remaining %, Budget Burned %, Burn Rate
- Target, Status, Time Window, Alert Policies

---

## Version History

- **v1.6**: Added error budget burn analysis with Status API v2 integration
- **v1.5**: Added SLO query extraction, hyperlinks, and improved export structure
- **v1.4**: Fixed critical metrics display and improved reliability
- **v1.3**: Enhanced error handling and added interactive export options
- **v1.2**: Integrated Nobl9 Reports API and improved efficiency
- **v1.1**: Added Excel export and enhanced data source analysis
- **v1.0**: Initial release with core analysis features
