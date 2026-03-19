#!/usr/bin/env python3
"""
SLO Creation Report Script

Tracks and reports on newly created SLOs and Composite SLOs within a specified time window.
Features:
- Time period selection (1 week, 2 weeks, 1 month, 3 months)
- User information resolution (names and emails)
- Grouping by project and service
- Excel/CSV export with comprehensive details
- Hyperlinks to SLOs in Nobl9 UI
"""

import json
import sys
import subprocess
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

try:
    import pandas as pd
    import openpyxl
    from openpyxl.styles import Alignment
    import colorama
    colorama.init()
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Install with: pip install pandas openpyxl colorama")
    sys.exit(1)

# Import from account_analyzer (same directory)
try:
    from account_analyzer import (
        enhanced_choose_context,
        get_credentials_for_context,
        authenticate
    )
except ImportError as e:
    print(f"Error importing from account_analyzer: {e}")
    sys.exit(1)

# Import user fetching functions from users_basic_v1.2
import importlib.util
user_scripts_path = Path(__file__).parent.parent / "user_scripts" / "users_basic_v1.2.py"
if not user_scripts_path.exists():
    print(f"ERROR: users_basic_v1.2.py not found at {user_scripts_path}")
    sys.exit(1)

spec = importlib.util.spec_from_file_location("users_basic_v1_2", user_scripts_path)
if spec and spec.loader:
    users_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(users_module)
    fetch_users = users_module.fetch_users
else:
    print("ERROR: Could not load users_basic_v1.2.py")
    sys.exit(1)


@dataclass
class NewSLOInfo:
    """Information about a newly created SLO."""
    name: str
    display_name: str
    slo_type: str  # "Regular" or "Composite"
    project: str
    service: str
    description: str
    component_count: Optional[int]
    created_at: str
    created_by: str
    days_since_creation: int


def print_colored(text: str, color: str = "") -> None:
    """Print colored text to console."""
    print(f"{color}{text}{colorama.Fore.RESET}")


def print_header(text: str) -> None:
    """Print a formatted header section."""
    print_colored(f"\n{'='*60}", colorama.Fore.CYAN)
    print_colored(text, colorama.Fore.CYAN)
    print_colored('='*60, colorama.Fore.CYAN)


class SLOCreationAnalyzer:
    """Analyzer for tracking SLO creation within a time window."""
    
    def __init__(self, context_name: Optional[str] = None):
        """Initialize the analyzer."""
        self.context_name = context_name
        self.access_token = None
        self.organization_id = None
        self.base_url = "https://app.nobl9.com"
        self.is_custom_instance = False
        self.new_slos: List[NewSLOInfo] = []
        self.user_lookup: Dict[str, Dict[str, str]] = {}  # user_id -> {name, email}
        self.time_window_days = 0
        self.start_date = None
        self.end_date = None
    
    def setup_authentication(self):
        """Setup authentication and context."""
        print_header("AUTHENTICATION")
        
        if self.context_name:
            print_colored(f"Using specified context: {self.context_name}", colorama.Fore.GREEN)
            credentials = get_credentials_for_context(self.context_name)
            if not credentials:
                print_colored(f"Context '{self.context_name}' not found", colorama.Fore.RED)
                sys.exit(1)
        else:
            self.context_name, credentials = enhanced_choose_context()
            print_colored(f"Selected context: {self.context_name}", colorama.Fore.GREEN)
        
        token, org_id, is_custom_instance, base_url = authenticate(credentials)
        
        self.access_token = token
        self.organization_id = org_id
        self.is_custom_instance = is_custom_instance
        if is_custom_instance and base_url:
            self.base_url = base_url
        
        print_colored("✓ Authentication successful", colorama.Fore.GREEN)
    
    def select_time_period(self):
        """Prompt user to select time period."""
        print_header("SELECT TIME PERIOD")
        print("Choose a time period to analyze:")
        print("  [1] Last 1 week (7 days)")
        print("  [2] Last 2 weeks (14 days)")
        print("  [3] Last 1 month (30 days)")
        print("  [4] Last 3 months (90 days)")
        
        try:
            choice = input("\nEnter your choice (1-4): ").strip()
            
            time_periods = {
                '1': 7,
                '2': 14,
                '3': 30,
                '4': 90
            }
            
            if choice not in time_periods:
                print_colored("Invalid choice. Using default: 30 days", colorama.Fore.YELLOW)
                choice = '3'
            
            self.time_window_days = time_periods[choice]
            self.end_date = datetime.now()
            self.start_date = self.end_date - timedelta(days=self.time_window_days)
            
            print_colored(f"\n✓ Selected: Last {self.time_window_days} days", colorama.Fore.GREEN)
            print_colored(f"  From: {self.start_date.strftime('%Y-%m-%d %H:%M:%S')}", colorama.Fore.WHITE)
            print_colored(f"  To:   {self.end_date.strftime('%Y-%m-%d %H:%M:%S')}", colorama.Fore.WHITE)
            
        except KeyboardInterrupt:
            print_colored("\n\nOperation cancelled by user", colorama.Fore.YELLOW)
            sys.exit(0)
    
    def _run_sloctl_command(self, args: List[str]) -> List[Dict]:
        """Run sloctl command and return parsed JSON output."""
        try:
            result = subprocess.run(
                ["sloctl"] + args + ["-o", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout) if result.stdout else []
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print_colored(f"Error running sloctl command: {e}", colorama.Fore.YELLOW)
            return []
    
    def collect_new_slos(self):
        """Collect SLOs created within the time window."""
        print_header("COLLECTING SLOS")
        print("Collecting all SLOs...")
        
        data = self._run_sloctl_command(["get", "slos", "-A"])
        
        if not data or not isinstance(data, list):
            print_colored("No SLO data found", colorama.Fore.YELLOW)
            return
        
        regular_count = 0
        composite_count = 0
        
        for item in data:
            metadata = item.get("metadata", {})
            spec = item.get("spec", {})
            objectives = spec.get("objectives", [])
            
            # Get creation date
            created_at_str = spec.get("createdAt", "")
            if not created_at_str:
                continue
            
            try:
                # Parse ISO format: 2023-05-05T07:21:16Z
                created_at = datetime.strptime(created_at_str, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                try:
                    # Try alternate format
                    created_at = datetime.strptime(created_at_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    continue
            
            # Check if within time window
            if not (self.start_date <= created_at <= self.end_date):
                continue
            
            # Check if composite
            is_composite = False
            component_count = None
            for objective in objectives:
                if "composite" in objective and "components" in objective.get("composite", {}):
                    is_composite = True
                    components = objective.get("composite", {}).get("components", {}).get("objectives", [])
                    component_count = len(components)
                    break
            
            # Calculate days since creation
            days_since = (self.end_date - created_at).days
            
            slo = NewSLOInfo(
                name=metadata.get("name", ""),
                display_name=metadata.get("displayName", "") or metadata.get("name", ""),
                slo_type="Composite" if is_composite else "Regular",
                project=metadata.get("project", ""),
                service=spec.get("service", ""),
                description=spec.get("description", ""),
                component_count=component_count if is_composite else None,
                created_at=created_at_str,
                created_by=spec.get("createdBy", ""),
                days_since_creation=days_since
            )
            
            self.new_slos.append(slo)
            
            if is_composite:
                composite_count += 1
            else:
                regular_count += 1
        
        # Sort by creation date (newest first)
        self.new_slos.sort(key=lambda x: x.created_at, reverse=True)
        
        total = regular_count + composite_count
        print_colored(f"\n✓ Found {total} new SLOs created in the last {self.time_window_days} days", colorama.Fore.GREEN)
        print_colored(f"  • Regular SLOs: {regular_count}", colorama.Fore.WHITE)
        print_colored(f"  • Composite SLOs: {composite_count}", colorama.Fore.WHITE)
    
    def fetch_user_information(self):
        """Fetch user information to resolve user IDs."""
        if not self.new_slos:
            return
        
        print_header("FETCHING USER INFORMATION")
        print("Resolving user IDs to names and emails...")
        
        try:
            # Determine custom base URL for fetch_users
            # fetch_users expects the base URL without /api (it adds /api/usrmgmt/v2/users internally)
            custom_base_url = None
            if self.is_custom_instance and self.base_url:
                # Remove /api if present, fetch_users will add it
                if self.base_url.endswith('/api'):
                    custom_base_url = self.base_url[:-4]  # Remove '/api'
                else:
                    custom_base_url = self.base_url
            
            users = fetch_users(self.access_token, custom_base_url, is_custom_instance=self.is_custom_instance)
            
            if users:
                for user in users:
                    user_id = user.get("id", "")
                    if user_id:
                        self.user_lookup[user_id] = {
                            "name": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or user_id,
                            "email": user.get("email", "")
                        }
                
                print_colored(f"✓ Loaded {len(self.user_lookup)} users", colorama.Fore.GREEN)
            else:
                print_colored("⚠ No user data retrieved", colorama.Fore.YELLOW)
        
        except Exception as e:
            print_colored(f"Error fetching users: {e}", colorama.Fore.YELLOW)
    
    def resolve_user_info(self, user_id: str) -> Tuple[str, str]:
        """Resolve user ID to name and email."""
        if not user_id:
            return ("", "")
        
        user_info = self.user_lookup.get(user_id, {})
        return (user_info.get("name", user_id), user_info.get("email", ""))
    
    def _get_base_url_for_links(self) -> str:
        """Get the base URL for hyperlinks, handling custom instances."""
        if self.is_custom_instance and self.base_url:
            # Remove /api if present for web UI URLs
            return self.base_url.replace('/api', '')
        return "https://app.nobl9.com"
    
    def _adjust_column_widths(self, worksheet, dataframe) -> None:
        """Auto-adjust column widths based on content."""
        for idx, col in enumerate(dataframe.columns, 1):
            max_length = max(
                dataframe[col].astype(str).apply(len).max(),
                len(col)
            )
            worksheet.column_dimensions[openpyxl.utils.get_column_letter(idx)].width = min(max_length + 2, 50)
    
    def export_to_excel(self) -> Optional[str]:
        """Export SLO creation report to Excel."""
        if not self.new_slos:
            print_colored("\n⚠ No new SLOs found in the selected time period", colorama.Fore.YELLOW)
            return None
        
        print_header("EXPORTING TO EXCEL")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"slo_creation_report_{self.context_name}_{self.time_window_days}days_{timestamp}.xlsx"
        
        try:
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                # Prepare data
                data = []
                for slo in self.new_slos:
                    user_name, user_email = self.resolve_user_info(slo.created_by)
                    
                    # Format created_at for display
                    try:
                        created_dt = datetime.strptime(slo.created_at, "%Y-%m-%dT%H:%M:%SZ")
                        created_display = created_dt.strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        created_display = slo.created_at
                    
                    data.append({
                        'Name': slo.name,
                        'Display Name': slo.display_name,
                        'Type': slo.slo_type,
                        'Project': slo.project,
                        'Service': slo.service,
                        'Description': slo.description,
                        'Component Count': slo.component_count if slo.component_count else "",
                        'Created At': created_display,
                        'Created By Name': user_name,
                        'Created By Email': user_email,
                        'Days Since Creation': slo.days_since_creation
                    })
                
                df = pd.DataFrame(data)
                df.to_excel(writer, sheet_name='New SLOs', index=False)
                
                worksheet = writer.sheets['New SLOs']
                
                # Auto-adjust column widths
                self._adjust_column_widths(worksheet, df)
                
                # Add hyperlinks to Display Name column
                if self.organization_id:
                    try:
                        base_url = self._get_base_url_for_links()
                        display_name_col_idx = list(df.columns).index('Display Name') + 1
                        for row_idx, slo in enumerate(self.new_slos, start=2):
                            cell = worksheet.cell(row=row_idx, column=display_name_col_idx)
                            slo_url = f"{base_url}/slo/overview/{slo.project}/{slo.name}?org={self.organization_id}&opt=currentTimeWindow"
                            cell.hyperlink = slo_url
                            cell.style = "Hyperlink"
                    except ValueError:
                        # Display Name column not found, skip hyperlinks
                        pass
            
            print_colored(f"✓ Excel file exported: {filename}", colorama.Fore.GREEN)
            return filename
            
        except Exception as e:
            print_colored(f"Error exporting to Excel: {e}", colorama.Fore.RED)
            import traceback
            traceback.print_exc()
            return None
    
    def export_to_csv(self) -> Optional[str]:
        """Export SLO creation report to CSV."""
        if not self.new_slos:
            print_colored("\n⚠ No new SLOs found in the selected time period", colorama.Fore.YELLOW)
            return None
        
        print_header("EXPORTING TO CSV")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"slo_creation_report_{self.context_name}_{self.time_window_days}days_{timestamp}.csv"
        
        try:
            # Prepare data
            data = []
            for slo in self.new_slos:
                user_name, user_email = self.resolve_user_info(slo.created_by)
                
                # Format created_at for display
                try:
                    created_dt = datetime.strptime(slo.created_at, "%Y-%m-%dT%H:%M:%SZ")
                    created_display = created_dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    created_display = slo.created_at
                
                data.append({
                    'Name': slo.name,
                    'Display Name': slo.display_name,
                    'Type': slo.slo_type,
                    'Project': slo.project,
                    'Service': slo.service,
                    'Description': slo.description,
                    'Component Count': slo.component_count if slo.component_count else "",
                    'Created At': created_display,
                    'Created By Name': user_name,
                    'Created By Email': user_email,
                    'Days Since Creation': slo.days_since_creation
                })
            
            df = pd.DataFrame(data)
            df.to_csv(filename, index=False)
            
            print_colored(f"✓ CSV file exported: {filename}", colorama.Fore.GREEN)
            return filename
            
        except Exception as e:
            print_colored(f"Error exporting to CSV: {e}", colorama.Fore.RED)
            return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SLO Creation Report - Track newly created SLOs",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--context", "-c",
        type=str,
        help="Nobl9 context name to use"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["excel", "csv"],
        default="excel",
        help="Export format (default: excel)"
    )
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = SLOCreationAnalyzer(context_name=args.context)
    
    try:
        # Setup authentication
        analyzer.setup_authentication()
        
        # Select time period
        analyzer.select_time_period()
        
        # Collect new SLOs
        analyzer.collect_new_slos()
        
        # Fetch user information
        analyzer.fetch_user_information()
        
        # Export
        if args.format == "excel":
            filename = analyzer.export_to_excel()
        else:
            filename = analyzer.export_to_csv()
        
        if filename:
            print_colored(f"\n✓ Report complete! File: {filename}", colorama.Fore.GREEN)
        else:
            print_colored("\n✗ Export failed or no data to export", colorama.Fore.RED)
            sys.exit(1)
            
    except KeyboardInterrupt:
        print_colored("\n\nOperation cancelled by user", colorama.Fore.YELLOW)
        sys.exit(1)
    except Exception as e:
        print_colored(f"\nError: {e}", colorama.Fore.RED)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
