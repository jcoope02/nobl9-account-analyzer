# Nobl9 Account Analyzer

A comprehensive Python tool for analyzing Nobl9 SLO platform accounts, providing detailed insights into project health, SLO coverage, alert policy effectiveness, and resource utilization.

## Overview

The Nobl9 Account Analyzer is designed to help organizations understand and optimize their SLO implementation across projects. It provides actionable insights through detailed analysis of projects, SLOs, alert policies, services, and user activity patterns.

## Features

### Core Analysis
- **Project Analysis**: Comprehensive overview of all projects with SLO, service, and alert policy counts
- **SLO Coverage Analysis**: Identifies SLOs with and without alert policies
- **Alert Policy Effectiveness**: Analyzes policy usage and identifies unused policies
- **Service Analysis**: Service-level SLO distribution and coverage metrics
- **Data Source Analysis**: Breakdown of monitoring tools and data source utilization

### Advanced Analytics
- **SLO Objective Analysis**: Target value distributions and time window patterns
- **Recent Changes Tracking**: Most recently updated SLOs with timestamps
- **Audit Trail Analysis**: User activity patterns and change breakdowns
- **Resource Utilization**: Official usage metrics from Nobl9 Reports API

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
git clone <repository-url>
cd account_analysis
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure `sloctl` is installed and configured:
```bash
sloctl config view
```

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
- **SLOs**: Detailed SLO information
- **Alert Policies**: Policy details and usage
- **Services**: Service information and SLO counts
- **SLOs without Alert Policies**: Uncovered SLOs
- **Unused Alert Policies**: Policies not attached to SLOs
- **Top Services by SLO Count**: Service rankings
- **Data Source Analysis**: Data source utilization
- **Time Window Analysis**: Time window patterns
- **Recent SLO Changes**: Recently modified SLOs
- **Top 10 Most Active Users**: User activity rankings
- **User Activity**: Detailed user statistics
- **Event Types**: Audit event breakdowns

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

- Audit log analysis requires appropriate permissions
- Some features may be limited in trial accounts
- Large organizations may experience longer processing times
- Custom instance configurations require proper URL setup

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

## Support

For issues related to:
- **Nobl9 Platform**: Contact Nobl9 support
- **Script Functionality**: Check error messages and logs
- **Configuration**: Refer to `sloctl` documentation

## License

This tool is provided as-is for analysis purposes. Ensure compliance with your organization's security and data handling policies.

## Version History

- **v1.0**: Initial release with core analysis features
- **v1.1**: Added Excel export and enhanced data source analysis
- **v1.2**: Integrated Nobl9 Reports API and improved efficiency
- **v1.3**: Enhanced error handling and added interactive export options
