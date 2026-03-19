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
    project_display_name: str
    service: str
    description: str
    component_count: Optional[int]
    slo_units: int  # Number of objectives/components (billing units)
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
        self.project_lookup: Dict[str, str] = {}  # project_name -> display_name
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
        
        # Switch sloctl context
        print_colored(f"\nSwitching to context: {self.context_name}", colorama.Fore.CYAN)
        try:
            subprocess.run(
                ["sloctl", "config", "use-context", self.context_name],
                capture_output=True, text=True, check=True
            )
            print_colored("✓ Context switched successfully", colorama.Fore.GREEN)
        except subprocess.CalledProcessError as e:
            print_colored(f"ERROR: Failed to switch context: {e}", colorama.Fore.RED)
            if e.stderr:
                print_colored(f"stderr: {e.stderr}", colorama.Fore.RED)
            sys.exit(1)
        
        print_colored(f"Organization: {self.organization_id}", colorama.Fore.GREEN)
    
    def select_time_period(self):
        """Prompt user to select time period."""
        print_header("SELECT TIME PERIOD")
        print("Choose a time period to analyze:")
        print("  [1] Last 1 week (7 days)")
        print("  [2] Last 2 weeks (14 days)")
        print("  [3] Last 1 month (30 days)")
        print("  [4] Last 3 months (90 days)")
        print("  [5] Last 4 months (120 days)")
        
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            time_periods = {
                '1': 7,
                '2': 14,
                '3': 30,
                '4': 90,
                '5': 120
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
    
    def collect_projects(self):
        """Collect all projects to get display names."""
        print("Collecting projects...")
        
        # Note: 'get projects' doesn't support -A flag, it gets all projects by default
        data = self._run_sloctl_command(["get", "projects"])
        
        if data and isinstance(data, list):
            for item in data:
                metadata = item.get("metadata", {})
                project_name = metadata.get("name", "")
                project_display_name = metadata.get("displayName", "") or project_name
                if project_name:
                    self.project_lookup[project_name] = project_display_name
            
            print_colored(f"✓ Loaded {len(self.project_lookup)} projects", colorama.Fore.GREEN)
    
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
            
            # Check if composite and calculate SLO Units
            is_composite = False
            component_count = None
            slo_units = 0
            
            for objective in objectives:
                if "composite" in objective and "components" in objective.get("composite", {}):
                    is_composite = True
                    components = objective.get("composite", {}).get("components", {}).get("objectives", [])
                    component_count = len(components)
                    # For composite SLOs, each component = 1 SLO Unit
                    slo_units = component_count
                    break
            
            # For regular SLOs, each objective = 1 SLO Unit
            if not is_composite:
                slo_units = len(objectives)
            
            # Calculate days since creation
            days_since = (self.end_date - created_at).days
            
            project_name = metadata.get("project", "")
            project_display_name = self.project_lookup.get(project_name, project_name)
            
            slo = NewSLOInfo(
                name=metadata.get("name", ""),
                display_name=metadata.get("displayName", "") or metadata.get("name", ""),
                slo_type="Composite" if is_composite else "Regular",
                project=project_name,
                project_display_name=project_display_name,
                service=spec.get("service", ""),
                description=spec.get("description", ""),
                component_count=component_count if is_composite else None,
                slo_units=slo_units,
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
        """Fetch user information to resolve user IDs (optimized to only fetch needed users)."""
        if not self.new_slos:
            return
        
        print_header("FETCHING USER INFORMATION")
        
        # First, identify unique user IDs we need to resolve
        unique_user_ids = set()
        for slo in self.new_slos:
            if slo.created_by:
                unique_user_ids.add(slo.created_by)
        
        if not unique_user_ids:
            print_colored("No user IDs to resolve", colorama.Fore.YELLOW)
            return
        
        print(f"Found {len(unique_user_ids)} unique creators to resolve...")
        print("Fetching user information from Nobl9 API...")
        
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
            
            # Note: Nobl9 API doesn't support fetching individual users by ID
            # Must fetch all users and filter, but we only build lookup for needed IDs
            users = fetch_users(
                self.access_token,
                self.organization_id,
                self.is_custom_instance,
                custom_base_url
            )
            
            if users:
                resolved_count = 0
                for user in users:
                    user_id = user.get("id", "")
                    # Only process users we actually need
                    if user_id and user_id in unique_user_ids:
                        first_name = user.get('firstName', '').strip()
                        last_name = user.get('lastName', '').strip()
                        
                        # Build full name, fallback to email or Unknown User
                        if first_name or last_name:
                            full_name = f"{first_name} {last_name}".strip()
                        elif user.get("email"):
                            full_name = user.get("email")
                        else:
                            full_name = "Unknown User"
                        
                        self.user_lookup[user_id] = {
                            "name": full_name,
                            "email": user.get("email", "")
                        }
                        resolved_count += 1
                
                print_colored(f"✓ Resolved {resolved_count} of {len(unique_user_ids)} creators", colorama.Fore.GREEN)
                
                # Show any unresolved user IDs
                unresolved = unique_user_ids - set(self.user_lookup.keys())
                if unresolved:
                    print_colored(f"⚠ Could not resolve {len(unresolved)} user IDs", colorama.Fore.YELLOW)
            else:
                print_colored("⚠ No user data retrieved", colorama.Fore.YELLOW)
        
        except Exception as e:
            print_colored(f"Error fetching users: {e}", colorama.Fore.YELLOW)
    
    def resolve_user_info(self, user_id: str) -> Tuple[str, str]:
        """Resolve user ID to name and email."""
        if not user_id:
            return ("", "")
        
        user_info = self.user_lookup.get(user_id)
        if user_info:
            return (user_info.get("name", "Unknown User"), user_info.get("email", ""))
        else:
            # User not found in lookup - show as unknown
            return ("Unknown User", "")
    
    def display_console_report(self):
        """Display creation report in console."""
        if not self.new_slos:
            print_colored("\n⚠ No new SLOs found in the selected time period", colorama.Fore.YELLOW)
            return
        
        print_header("SLO CREATION REPORT")
        print_colored(f"Time Period: Last {self.time_window_days} Days", colorama.Fore.WHITE)
        print_colored(f"  From: {self.start_date.strftime('%Y-%m-%d %H:%M:%S')}", colorama.Fore.WHITE)
        print_colored(f"  To:   {self.end_date.strftime('%Y-%m-%d %H:%M:%S')}", colorama.Fore.WHITE)
        print_colored(f"Organization: {self.organization_id}", colorama.Fore.WHITE)
        
        # Summary
        print_header("SUMMARY")
        regular_count = sum(1 for slo in self.new_slos if slo.slo_type == "Regular")
        composite_count = sum(1 for slo in self.new_slos if slo.slo_type == "Composite")
        total_slo_units = sum(slo.slo_units for slo in self.new_slos)
        
        print_colored(f"Total New SLOs Created: {len(self.new_slos)}", colorama.Fore.WHITE)
        print_colored(f"  • Regular SLOs: {regular_count}", colorama.Fore.GREEN)
        print_colored(f"  • Composite SLOs: {composite_count}", colorama.Fore.GREEN)
        print_colored(f"Total SLO Units Created: {total_slo_units}", colorama.Fore.WHITE)
        
        # Projects with new SLOs
        projects = set(slo.project for slo in self.new_slos)
        print_colored(f"Projects with New SLOs: {len(projects)}", colorama.Fore.WHITE)
        
        # Most active creator
        creator_counts = {}
        for slo in self.new_slos:
            creator_name, _ = self.resolve_user_info(slo.created_by)
            if creator_name:
                creator_counts[creator_name] = creator_counts.get(creator_name, 0) + 1
        
        if creator_counts:
            most_active = max(creator_counts.items(), key=lambda x: x[1])
            print_colored(f"Most Active Creator: {most_active[0]} ({most_active[1]} SLOs)", colorama.Fore.WHITE)
        
        # New SLOs by Project
        print_header("NEW SLOS BY PROJECT")
        
        # Group by project and service
        project_service_slos = {}
        for slo in self.new_slos:
            key = (slo.project, slo.service)
            if key not in project_service_slos:
                project_service_slos[key] = []
            project_service_slos[key].append(slo)
        
        # Sort by project, then service
        for (project, service) in sorted(project_service_slos.keys()):
            # Get project display name
            slos = project_service_slos[(project, service)]
            project_display = slos[0].project_display_name if slos else project
            
            print_colored(f"\nProject: {project_display}", colorama.Fore.CYAN)
            if project_display != project:
                print_colored(f"  ({project})", colorama.Fore.CYAN)
            print_colored("-" * 60, colorama.Fore.CYAN)
            print_colored(f"Service: {service}", colorama.Fore.YELLOW)
            
            slos = project_service_slos[(project, service)]
            for slo in sorted(slos, key=lambda x: x.created_at, reverse=True):
                user_name, user_email = self.resolve_user_info(slo.created_by)
                
                # Format created_at
                try:
                    created_dt = datetime.strptime(slo.created_at, "%Y-%m-%dT%H:%M:%SZ")
                    created_display = created_dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    created_display = slo.created_at
                
                slo_type_display = f"[{slo.slo_type}]"
                if slo.component_count:
                    slo_type_display += f" ({slo.component_count} components)"
                
                print_colored(f"  {slo_type_display} {slo.display_name or slo.name}", colorama.Fore.WHITE)
                print_colored(f"    Created: {created_display}", colorama.Fore.WHITE)
                if user_name:
                    print_colored(f"    Created By: {user_name} ({user_email})", colorama.Fore.WHITE)
        
        # Creation Timeline
        print_header("CREATION TIMELINE")
        
        # Group by week
        week_counts = {}
        for slo in self.new_slos:
            try:
                created_dt = datetime.strptime(slo.created_at, "%Y-%m-%dT%H:%M:%SZ")
                # Get start of week (Monday)
                week_start = created_dt - timedelta(days=created_dt.weekday())
                week_key = week_start.strftime("%Y-%m-%d")
                week_counts[week_key] = week_counts.get(week_key, 0) + 1
            except ValueError:
                continue
        
        for week in sorted(week_counts.keys()):
            count = week_counts[week]
            print_colored(f"Week of {week}: {count} SLOs", colorama.Fore.WHITE)
        
        # SLOs by Project Summary
        print_header("SLOS BY PROJECT")
        
        # Group by project
        project_counts = {}
        project_display_names = {}
        for slo in self.new_slos:
            project_counts[slo.project] = project_counts.get(slo.project, 0) + 1
            project_display_names[slo.project] = slo.project_display_name
        
        # Sort by count descending
        sorted_projects = sorted(project_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Display all projects with color coding
        print()
        for project, count in sorted_projects:
            display_name = project_display_names.get(project, project)
            
            # Color code by count
            if count >= 20:
                color = colorama.Fore.GREEN
            elif count >= 10:
                color = colorama.Fore.YELLOW
            elif count >= 5:
                color = colorama.Fore.CYAN
            else:
                color = colorama.Fore.WHITE
            
            # Format: "count display_name (technical_name)"
            if display_name != project:
                print_colored(f"  {count:3d} SLOs - {display_name} ({project})", color)
            else:
                print_colored(f"  {count:3d} SLOs - {display_name}", color)
        
        # Top Creators
        print_header("TOP CREATORS")
        
        # Sort creators by count
        sorted_creators = sorted(creator_counts.items(), key=lambda x: x[1], reverse=True)
        
        for i, (creator, count) in enumerate(sorted_creators[:10], 1):
            # Get email for this creator
            email = ""
            for slo in self.new_slos:
                creator_name, creator_email = self.resolve_user_info(slo.created_by)
                if creator_name == creator:
                    email = creator_email
                    break
            
            print_colored(f"{i:2d}. {creator} ({email}) - {count} SLOs", colorama.Fore.WHITE)
    
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
                # Tab 1: Summary by Project
                project_summary = {}
                project_display_names = {}
                project_regular_counts = {}
                project_composite_counts = {}
                project_slo_units = {}
                
                for slo in self.new_slos:
                    project = slo.project
                    project_summary[project] = project_summary.get(project, 0) + 1
                    project_display_names[project] = slo.project_display_name
                    project_slo_units[project] = project_slo_units.get(project, 0) + slo.slo_units
                    
                    if slo.slo_type == "Regular":
                        project_regular_counts[project] = project_regular_counts.get(project, 0) + 1
                    else:
                        project_composite_counts[project] = project_composite_counts.get(project, 0) + 1
                
                summary_data = []
                for project in sorted(project_summary.keys(), key=lambda x: project_summary[x], reverse=True):
                    summary_data.append({
                        'Project': project,
                        'Project Display Name': project_display_names[project],
                        'Total SLOs': project_summary[project],
                        'Regular SLOs': project_regular_counts.get(project, 0),
                        'Composite SLOs': project_composite_counts.get(project, 0),
                        'SLO Units': project_slo_units[project]
                    })
                
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary by Project', index=False)
                
                # Auto-adjust column widths for summary
                summary_worksheet = writer.sheets['Summary by Project']
                self._adjust_column_widths(summary_worksheet, summary_df)
                
                # Tab 2: Detailed SLO data
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
                        'Project Display Name': slo.project_display_name,
                        'Service': slo.service,
                        'Description': slo.description,
                        'Component Count': slo.component_count if slo.component_count else "",
                        'SLO Units': slo.slo_units,
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
                    'Project Display Name': slo.project_display_name,
                    'Service': slo.service,
                    'Description': slo.description,
                    'Component Count': slo.component_count if slo.component_count else "",
                    'SLO Units': slo.slo_units,
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
        
        # Collect projects (for display names)
        analyzer.collect_projects()
        
        # Collect new SLOs
        analyzer.collect_new_slos()
        
        # Fetch user information
        analyzer.fetch_user_information()
        
        # Display console report
        analyzer.display_console_report()
        
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
