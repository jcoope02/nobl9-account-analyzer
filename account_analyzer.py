#!/usr/bin/env python3
"""
Nobl9 Account Analyzer

A comprehensive tool for analyzing Nobl9 account data including:
- Project analysis and health scoring
- SLO coverage and alert policy effectiveness
- Service analysis and data source breakdown
- Multiple export formats (CSV, JSON, Excel)
- Audit trail analysis and user activity tracking
"""

import json
import os
import sys
import subprocess
import requests
import base64
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import argparse
import csv
import toml
from dataclasses import dataclass, asdict

# Cross-platform compatibility and colors
import colorama
colorama.init()


def print_colored(text: str, color: str, end: str = "\n") -> None:
    """Print colored text."""
    print(f"{color}{text}{colorama.Fore.RESET}", end=end)

def print_header(text: str) -> None:
    """Print a formatted header."""
    print_colored(f"\n{text}", colorama.Fore.CYAN)
    print_colored("=" * len(text), colorama.Fore.CYAN)

# Data structures for analysis
@dataclass
class ProjectInfo:
    name: str
    display_name: str
    description: str
    created_at: str
    updated_at: str
    slo_count: int = 0
    service_count: int = 0
    alert_policy_count: int = 0

@dataclass
class SLOInfo:
    name: str
    project: str
    service: str
    description: str
    target: float
    time_window: str
    alert_policies: List[str]
    health_status: str
    created_at: str
    updated_at: str

@dataclass
class CompositeSLOComponent:
    name: str
    weight: float
    normalized_weight: float
    when_delayed: str
    target: float

@dataclass
class CompositeSLOInfo:
    name: str
    project: str
    description: str
    components: List[CompositeSLOComponent]  # List of component SLOs with details
    component_count: int
    target: float
    time_window: str
    alert_policies: List[str]
    health_status: str
    created_at: str
    updated_at: str

@dataclass
class AlertPolicyInfo:
    name: str
    project: str
    description: str
    severity: str
    conditions: List[Dict]
    created_at: str
    updated_at: str
    used_by_slos: int = 0

@dataclass
class ServiceInfo:
    name: str
    project: str
    description: str
    created_at: str
    updated_at: str
    slo_count: int = 0

@dataclass
class AuditLogEntry:
    timestamp: str
    actor: Dict[str, str]
    event: str
    object_type: str
    object_name: str
    project: str

@dataclass
class AccountSummary:
    total_projects: int
    total_slos: int
    total_composite_slos: int
    total_composite_components: int
    total_services: int
    total_alert_policies: int
    total_alerts: int
    total_data_sources: int
    slo_coverage: float
    top_active_users: List[Tuple[str, int]]
    most_active_project: str
    last_7_days_changes: int
    # API metrics
    total_users: int
    total_slo_units: int

def load_contexts_from_toml() -> Dict[str, Dict[str, Any]]:
    """Load and parse TOML configuration."""
    # Cross-platform path handling for Windows, macOS, and Linux
    if os.name == 'nt':  # Windows
        default_toml_path = os.path.join(
            os.path.expanduser("~"), "AppData", "Local", "nobl9", "config.toml"
        )
    else:  # macOS and Linux
        default_toml_path = os.path.expanduser("~/.config/nobl9/config.toml")

    if not os.path.isfile(default_toml_path):
        print(f"TOML config file not found at expected path: {default_toml_path}")
        try:
            user_path = input("Please provide the full path to your Nobl9 config.toml file: ").strip()
            if not os.path.isfile(user_path):
                print(f"ERROR: Could not find TOML file at {user_path}")
                return {}
            toml_path = user_path
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)
    else:
        toml_path = default_toml_path

    try:
        toml_data = toml.load(toml_path)
        raw_contexts = toml_data.get("contexts", {})
        parsed_contexts = {}

        for ctx_name, creds in raw_contexts.items():
            if "clientId" in creds and "clientSecret" in creds:
                is_custom_instance = "url" in creds
                base_url = creds.get("url")
                okta_org_url = creds.get("oktaOrgURL")
                okta_auth_server = creds.get("oktaAuthServer")

                parsed_contexts[ctx_name] = {
                    "clientId": creds["clientId"],
                    "clientSecret": creds["clientSecret"],
                    "accessToken": creds.get("accessToken", ""),
                    "organization": creds.get("organization", None),
                    "is_custom_instance": is_custom_instance,
                    "base_url": base_url,
                    "oktaOrgURL": okta_org_url,
                    "oktaAuthServer": okta_auth_server
                }
        return parsed_contexts
    except Exception as e:
        print(f"Failed to parse TOML config: {e}")
        return {}

def enhanced_choose_context() -> Tuple[str, Dict[str, Any]]:
    """Enhanced context selection with custom instance support."""
    contexts_dict = load_contexts_from_toml()
    if not contexts_dict:
        print("No valid contexts found. Please ensure your config.toml is set up correctly.")
        sys.exit(1)

    context_names = list(contexts_dict.keys())
    if len(context_names) == 1:
        selected = context_names[0]
        return selected, contexts_dict[selected]

    print(f"\nAvailable contexts:")
    for i, name in enumerate(context_names, 1):
        print(f"  [{i}] {name}")

    try:
        choice = input("Select a context: ").strip()
        index = int(choice) - 1
        selected = context_names[index]
        return selected, contexts_dict[selected]
    except (ValueError, IndexError):
        print("ERROR: Invalid context selection.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

def authenticate(credentials: Dict[str, Any]) -> Tuple[str, str, bool, Optional[str]]:
    """Authenticate with Nobl9 API using credentials."""
    client_id = credentials.get("clientId")
    client_secret = credentials.get("clientSecret")
    if not client_id or not client_secret:
        print("ERROR: Missing credentials in context.")
        sys.exit(1)

    org_id = credentials.get("organization")
    if not org_id and credentials.get("accessToken"):
        org_id = decode_jwt_payload(credentials["accessToken"])
    if not org_id:
        org_id = os.getenv("SLOCTL_ORGANIZATION")
    if not org_id:
        try:
            org_id = input("Enter Nobl9 Organization ID (find in Nobl9 UI under Settings > Account): ").strip()
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)

    if not org_id:
        print("ERROR: Organization ID is required.")
        sys.exit(1)

    creds_string = f"{client_id}:{client_secret}"
    encoded_creds = base64.b64encode(creds_string.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_creds}",
        "Content-Type": "application/json",
        "Organization": org_id
    }

    is_custom_instance = credentials.get("is_custom_instance", False)
    base_url = credentials.get("base_url")

    if is_custom_instance and base_url:
        print(f"API base url: {base_url}")
        auth_url = f"{base_url}/accessToken"
    else:
        auth_url = "https://app.nobl9.com/api/accessToken"

    try:
        response = requests.post(auth_url, headers=headers, timeout=30)
        if response.status_code != 200:
            print("ERROR: Authentication failed")
            try:
                error_data = response.json()
                if "error" in error_data:
                    error_info = error_data["error"]
                    if isinstance(error_info, str):
                        json_match = re.search(r'\{.*\}', error_info)
                        if json_match:
                            nested_error = json.loads(json_match.group())
                            print(f"  Error Code: {nested_error.get('errorCode', 'Unknown')}")
                            print(f"  Summary: {nested_error.get('errorSummary', 'No summary provided')}")
                        else:
                            print(f"  Error: {error_info}")
                    else:
                        print(f"  Error Code: {error_info.get('errorCode', 'Unknown')}")
                        print(f"  Summary: {error_info.get('errorSummary', 'No summary provided')}")
            except json.JSONDecodeError:
                print(f"  Raw response: {response.text}")
            sys.exit(1)

        token_data = response.json()
        token = token_data.get("access_token")
        if not token:
            print("ERROR: No access token in response")
            print(f"  Response: {response.text}")
            sys.exit(1)
        return token, org_id, is_custom_instance, base_url
    except requests.exceptions.Timeout:
        print("ERROR: Authentication request timed out")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error during authentication: {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("ERROR: Invalid JSON response from authentication endpoint")
        print(f"  Response: {response.text}")
        sys.exit(1)

def decode_jwt_payload(token):
    """Decode JWT token to extract organization info."""
    try:
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        return payload.get('m2mProfile', {}).get('organization', None)
    except Exception:
        return None

class Nobl9AccountAnalyzer:
    """Main class for analyzing Nobl9 account data"""
    
    def __init__(self):
        """Initialize the analyzer"""
        self.access_token = None
        self.organization_id = None
        self.base_url = "https://app.nobl9.com"
        self.audit_base_url = "https://app.nobl9.com"
        self.is_custom_instance = False
        self.context_name = None  # Store the selected context name
        
        # Data storage
        self.projects: List[ProjectInfo] = []
        self.slos: List[SLOInfo] = []
        self.composite_slos: List[CompositeSLOInfo] = []  # Store composite SLOs
        self.alert_policies: List[AlertPolicyInfo] = []
        self.services: List[ServiceInfo] = []
        self.audit_logs: List[AuditLogEntry] = []
        self.raw_slo_data: List[Dict] = []  # Store raw SLO data for analysis
    
    def _setup_authentication(self, context_name: str = None):
        """Setup authentication using the same method as alert scripts"""
        print_colored("Setting up authentication...", colorama.Fore.CYAN)
        
        # Choose context and authenticate
        print_header("AUTHENTICATION")
        if context_name:
            print_colored(f"Using specified context: {context_name}", colorama.Fore.GREEN)
            credentials = get_credentials_for_context(context_name)
            if not credentials:
                print_colored(f"❌ Context '{context_name}' not found in configuration", colorama.Fore.RED)
                sys.exit(1)
        else:
            context_name, credentials = enhanced_choose_context()
            print_colored(f"Selected context: {context_name}", colorama.Fore.GREEN)

        token, org_id, is_custom_instance, base_url = authenticate(credentials)
        print_colored("✓ Authentication successful", colorama.Fore.GREEN)

        # Store authentication details
        self.access_token = token
        self.organization_id = org_id
        self.is_custom_instance = is_custom_instance
        self.context_name = context_name # Store context name
        
        if is_custom_instance and base_url:
            self.base_url = base_url
            self.audit_base_url = base_url
        
        # Switch sloctl context
        print_colored(f"\nSwitching to context: {context_name}", colorama.Fore.CYAN)
        try:
            result = subprocess.run(
                ["sloctl", "config", "use-context", context_name],
                capture_output=True, text=True, check=True
            )
            print_colored("✓ Context switched successfully", colorama.Fore.GREEN)
        except subprocess.CalledProcessError as e:
            print_colored(f"ERROR: Failed to switch context: {e}", colorama.Fore.RED)
            if e.stderr:
                print_colored(f"stderr: {e.stderr}", colorama.Fore.RED)
            sys.exit(1)
        
        print_colored(f"Loaded configuration for organization: {self.organization_id}", colorama.Fore.GREEN)
    
    def _get_access_token(self) -> str:
        """Get access token - now handled in _setup_authentication"""
        if not self.access_token:
            print("ERROR: No access token available. Please re-authenticate.")
            sys.exit(1)
        return self.access_token
    
    def _run_sloctl_command(self, command: List[str]) -> Dict[str, Any]:
        """Run sloctl command and return JSON output"""
        try:
            result = subprocess.run(
                ["sloctl"] + command + ["-o", "json"],
                capture_output=True, text=True, check=True
            )
            
            # Handle empty output gracefully
            if not result.stdout.strip():
                print(f"Warning: No data returned for command {' '.join(command)}")
                return []
            
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error running sloctl command {' '.join(command)}: {e}")
            return []
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON output for command {' '.join(command)}: {e}")
            print(f"Raw output: {result.stdout[:200]}...")
            return []
    
    def collect_projects(self):
        """Collect all projects from Nobl9"""
        print("Collecting projects...")
        data = self._run_sloctl_command(["get", "projects"])
        
        if data and isinstance(data, list):
            for item in data:
                project = ProjectInfo(
                    name=item.get("metadata", {}).get("name", ""),
                    display_name=item.get("metadata", {}).get("displayName", ""),
                    description=item.get("spec", {}).get("description", ""),
                    created_at=item.get("spec", {}).get("createdAt", ""),
                    updated_at=item.get("metadata", {}).get("generation", "")
                )
                self.projects.append(project)
        
        print("Collected projects")
    
    def collect_slos(self):
        """Collect all SLOs from all projects"""
        print("Collecting SLOs...")
        data = self._run_sloctl_command(["get", "slos", "-A"])
        
        # Store raw data for detailed analysis
        self.raw_slo_data = data if data and isinstance(data, list) else []
        
        if data and isinstance(data, list):
            for item in data:
                metadata = item.get("metadata", {})
                spec = item.get("spec", {})
                indicator = spec.get("indicator", {})
                
                # Check if this is a composite SLO by looking for objectives with composite components
                objectives = spec.get("objectives", [])
                composite_components = []
                
                for objective in objectives:
                    if "composite" in objective and "components" in objective.get("composite", {}):
                        
                        composite_spec = objective.get("composite", {})
                        component_objectives = composite_spec.get("components", {}).get("objectives", [])
                        
                        # Parse component details
                        for comp_obj in component_objectives:
                            component = CompositeSLOComponent(
                                name=f"{comp_obj.get('project', '')}/{comp_obj.get('slo', '')}/{comp_obj.get('objective', '')}",
                                weight=comp_obj.get("weight", 0.0),
                                normalized_weight=comp_obj.get("weight", 0.0),  # Will calculate normalized weight later
                                when_delayed=comp_obj.get("whenDelayed", ""),
                                target=comp_obj.get("target", 0.0)
                            )
                            composite_components.append(component)
                
                # If we found composite components, create the composite SLO
                if composite_components:
                    # Calculate normalized weights
                    total_weight = sum(comp.weight for comp in composite_components)
                    for comp in composite_components:
                        if total_weight > 0:
                            comp.normalized_weight = comp.weight / total_weight
                        else:
                            comp.normalized_weight = 0.0
                    
                    # Get the target from the composite objective
                    composite_target = 0.0
                    for objective in objectives:
                        if "composite" in objective and "components" in objective.get("composite", {}):
                            composite_target = objective.get("target", 0.0)
                            break
                    
                    composite_slo = CompositeSLOInfo(
                        name=metadata.get("name", ""),
                        project=metadata.get("project", ""),
                        description=spec.get("description", ""),
                        components=composite_components,
                        component_count=len(composite_components),
                        target=composite_target,
                        time_window=str(spec.get("timeWindows", [])),
                        alert_policies=spec.get("alertPolicies", []),
                        health_status=item.get("status", {}).get("health", "unknown"),
                        created_at=spec.get("createdAt", ""),
                        updated_at=item.get("status", {}).get("updatedAt", "")
                    )
                    self.composite_slos.append(composite_slo)
                
                # Regular SLO collection (existing code)
                # Get target from objectives if available, otherwise from spec
                slo_target = 0.0
                if objectives and not composite_components:  # Only for non-composite SLOs
                    for objective in objectives:
                        if "target" in objective:
                            slo_target = objective.get("target", 0.0)
                            break
                else:
                    slo_target = spec.get("target", 0.0)
                
                slo = SLOInfo(
                    name=metadata.get("name", ""),
                    project=metadata.get("project", ""),
                    service=spec.get("service", ""),
                    description=spec.get("description", ""),
                    target=slo_target,
                    time_window=str(spec.get("timeWindows", [])),
                    alert_policies=spec.get("alertPolicies", []),
                    health_status=item.get("status", {}).get("health", "unknown"),
                    created_at=spec.get("createdAt", ""),
                    updated_at=item.get("status", {}).get("updatedAt", "")
                )
                self.slos.append(slo)
        
        print(f"Collected SLOs (Total: {len(self.slos)}, Composite: {len(self.composite_slos)})")
    
    def collect_alert_policies(self):
        """Collect all alert policies from all projects"""
        print("Collecting alert policies...")
        data = self._run_sloctl_command(["get", "alertpolicies", "-A"])
        
        if data and isinstance(data, list):
            for item in data:
                metadata = item.get("metadata", {})
                spec = item.get("spec", {})
                
                policy = AlertPolicyInfo(
                    name=metadata.get("name", ""),
                    project=metadata.get("project", ""),
                    description=spec.get("description", ""),
                    severity=spec.get("severity", "unknown"),
                    conditions=spec.get("conditions", []),
                    created_at=metadata.get("creationTimestamp", ""),
                    updated_at=metadata.get("generation", "")
                )
                self.alert_policies.append(policy)
        else:
            print("No alert policies found or error occurred during collection")
        
        print(f"Collected {len(self.alert_policies)} alert policies")
    
    def collect_services(self):
        """Collect all services from all projects"""
        print("Collecting services...")
        data = self._run_sloctl_command(["get", "services", "-A"])
        
        if data and isinstance(data, list):
            for item in data:
                metadata = item.get("metadata", {})
                spec = item.get("spec", {})
                
                service = ServiceInfo(
                    name=metadata.get("name", ""),
                    project=metadata.get("project", ""),
                    description=spec.get("description", ""),
                    created_at=metadata.get("creationTimestamp", ""),
                    updated_at=metadata.get("generation", "")
                )
                self.services.append(service)
        
        print("Collected services")
    
    def collect_audit_logs(self, days: int = 7):
        """Collect audit logs for the last N days"""
        print(f"Collecting audit logs for last {days} days...")
        
        if not self.access_token:
            self.access_token = self._get_access_token()
        
        # Calculate date range (with timezone awareness)
        from datetime import timezone
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Organization": self.organization_id
        }
        
        try:
            # Get all audit logs with pagination
            all_logs = []
            offset = 0
            limit = 100
            
            # Format dates for API (ISO format with Z suffix)
            start_time = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_time = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            while True:
                # Handle different base URL formats for custom instances
                if self.is_custom_instance:
                    # For custom instances, check if base_url already includes /api
                    if self.audit_base_url.endswith('/api'):
                        url = f"{self.audit_base_url}/audit/v1/logs"
                    else:
                        url = f"{self.audit_base_url}/api/audit/v1/logs"
                else:
                    # Standard Nobl9 instance
                    url = f"{self.audit_base_url}/api/audit/v1/logs"
                
                params = {
                    "limit": limit,
                    "offset": offset,
                    "sortBy": "timestamp",
                    "sortOrder": "desc",
                    "from": start_time,
                    "to": end_time
                }
                
                response = requests.get(url, headers=headers, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    logs = data.get("data", [])
                    
                    if not logs:
                        break
                    
                    # Process logs (no need to filter by date since API handles it)
                    for log in logs:
                        audit_entry = AuditLogEntry(
                            timestamp=log.get("timestamp", ""),
                            actor=log.get("actor", {}),
                            event=log.get("event", ""),
                            object_type=log.get("data", {}).get("kind", ""),
                            object_name=log.get("data", {}).get("name", ""),
                            project=log.get("data", {}).get("namespace", "")
                        )
                        all_logs.append(audit_entry)
                    
                    offset += limit
                    
                    # Check if we've reached the end
                    if len(logs) < limit:
                        break
                else:
                    print(f"Failed to get audit logs: {response.status_code}")
                    if response.status_code == 401:
                        print("Note: Audit logs may require additional permissions")
                    break
            
            self.audit_logs = all_logs
            if all_logs:
                print(f"Collected {len(all_logs)} audit log entries")
            else:
                print("No audit logs collected (may require additional permissions)")
            
        except Exception as e:
            print(f"Error collecting audit logs: {e}")
            self.audit_logs = []
    
    def analyze_data(self) -> AccountSummary:
        """Analyze collected data and generate summary statistics"""
        print("Analyzing collected data...")
        
        # Count objects by project using single-pass counting
        project_counts = {}
        for slo in self.slos:
            project_counts.setdefault(slo.project, {'slo': 0, 'service': 0, 'policy': 0})['slo'] += 1
        
        for service in self.services:
            project_counts.setdefault(service.project, {'slo': 0, 'service': 0, 'policy': 0})['service'] += 1
        
        for policy in self.alert_policies:
            project_counts.setdefault(policy.project, {'slo': 0, 'service': 0, 'policy': 0})['policy'] += 1
        
        # Apply counts to projects
        for project in self.projects:
            counts = project_counts.get(project.name, {'slo': 0, 'service': 0, 'policy': 0})
            project.slo_count = counts['slo']
            project.service_count = counts['service']
            project.alert_policy_count = counts['policy']
        
        # Count SLOs using each alert policy using single-pass counting
        policy_usage = {policy.name: 0 for policy in self.alert_policies}
        for slo in self.slos:
            for policy_name in slo.alert_policies:
                if policy_name in policy_usage:
                    policy_usage[policy_name] += 1
        
        for policy in self.alert_policies:
            policy.used_by_slos = policy_usage.get(policy.name, 0)
        
        # Count SLOs per service using efficient dictionary lookup
        service_slo_counts = {}
        for slo in self.slos:
            key = (slo.service, slo.project)
            service_slo_counts[key] = service_slo_counts.get(key, 0) + 1
        
        for service in self.services:
            service.slo_count = service_slo_counts.get((service.name, service.project), 0)
        
        # Calculate coverage using sum with generator expression
        slos_with_policies = sum(1 for slo in self.slos if slo.alert_policies)
        slo_coverage = (slos_with_policies / len(self.slos)) * 100 if self.slos else 0
        
        # Build efficient lookup dictionary for raw SLO data
        slo_lookup = {}
        for raw_slo in self.raw_slo_data:
            name = raw_slo.get("metadata", {}).get("name", "")
            project = raw_slo.get("metadata", {}).get("project", "")
            if name and project:
                slo_lookup[(name, project)] = raw_slo
        
        # Process all SLO data in a single pass
        data_source_analysis = {}
        unique_data_sources = set()  # Track unique data sources
        
        for slo in self.slos:
            raw_slo_data = slo_lookup.get((slo.name, slo.project))
            
            if raw_slo_data:
                spec = raw_slo_data.get("spec", {})
                indicator = spec.get("indicator", {})
                
                if "metricSource" in indicator and "composite" not in indicator:
                    metric_source = indicator.get("metricSource", {})
                    source_name = metric_source.get("name", "")
                    source_kind = metric_source.get("kind", "")
                    
                    if source_name and "unknown" not in source_name.lower():
                        unique_data_sources.add(source_name)  # Add to set of unique sources
                        
                        # Build data source analysis in the same pass
                        if source_name not in data_source_analysis:
                            data_source_analysis[source_name] = {
                                'type': 'Unknown',
                                'kind': source_kind,
                                'slo_count': 0,
                                'projects': set(),
                                'services': set()
                            }
                        
                        data_source_analysis[source_name]['slo_count'] += 1
                        data_source_analysis[source_name]['projects'].add(slo.project)
                        data_source_analysis[source_name]['services'].add(slo.service)
        
        # Store lookup data for report generation
        self._slo_lookup = slo_lookup
        
        # Find most active users and projects from audit logs
        user_activity = {}
        project_activity = {}
        
        for log in self.audit_logs:
            # Parse user information from actor field
            actor = log.actor
            if actor and "user" in actor and actor["user"]:
                user_info = actor["user"]
                if "firstName" in user_info and "lastName" in user_info:
                    user = (f"{user_info['firstName'].strip()} "
                           f"{user_info['lastName'].strip()}")
                elif "id" in user_info:
                    user = user_info["id"]
                else:
                    user = "Unknown User"
            else:
                user = "System"
            user_activity[user] = user_activity.get(user, 0) + 1
            
            if log.project:
                project_activity[log.project] = project_activity.get(log.project, 0) + 1
        
        # Get top 10 most active users
        top_users = sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:10]
        most_active_project = (max(project_activity.items(), key=lambda x: x[1])[0] 
                              if project_activity else "unknown")
        
        # Get API metrics from usage summary
        total_users = 0
        total_slo_units = 0
        total_composite_components_api = 0
        
        if hasattr(self, '_usage_summary') and self._usage_summary:
            usage_data = self._usage_summary.get("usageSummary", {})
            metadata = self._usage_summary.get("metadata", {})
            
            # Get user count from API
            users_data = usage_data.get("users", {})
            if users_data:
                total_users = users_data.get("currentUsage", 0)
            
            # Get SLO units count from API
            slo_units_data = usage_data.get("sloUnits", {})
            if slo_units_data:
                total_slo_units = slo_units_data.get("currentUsage", 0)
            
            # Get composite SLO components count from API
            composite_components_data = usage_data.get("compositeSloComponents", {})
            if composite_components_data:
                total_composite_components_api = composite_components_data.get("currentUsage", 0)
        
        summary = AccountSummary(
            total_projects=len(self.projects),
            total_slos=len(self.slos),
            total_composite_slos=len(self.composite_slos),
            total_composite_components=sum(slo.component_count for slo in self.composite_slos),
            total_services=len(self.services),
            total_alert_policies=len(self.alert_policies),
            total_alerts=0,  # Will be implemented later
            total_data_sources=len(unique_data_sources),
            slo_coverage=slo_coverage,
            top_active_users=top_users,
            most_active_project=most_active_project,
            last_7_days_changes=len(self.audit_logs),
            # API metrics
            total_users=total_users,
            total_slo_units=total_slo_units
        )
        
        return summary
    
    def generate_report(self, summary: AccountSummary, output_format: str = "console"):
        """Generate report in specified format"""
        if output_format == "console":
            self._print_console_report(summary)
        elif output_format == "csv":
            self._export_csv(summary)
        elif output_format == "json":
            self._export_json(summary)
        elif output_format == "excel":
            self._export_excel(summary)
        elif output_format == "yaml":
            self._export_yaml(summary)
        else:
            print(f"Unsupported output format: {output_format}")
    
    def _print_console_report(self, summary: AccountSummary):
        """Print formatted report to console"""
        print_colored("\n" + "="*60, colorama.Fore.CYAN)
        print_colored("Nobl9 ACCOUNT ANALYSIS REPORT", colorama.Fore.CYAN)
        print_colored("="*60, colorama.Fore.CYAN)
        print_colored(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", colorama.Fore.WHITE)
        print_colored(f"Organization: {self.organization_id}", colorama.Fore.WHITE)
        print()
        
        # Executive Summary
        print_header("EXECUTIVE SUMMARY")
        print_colored(f"Total Projects: {summary.total_projects}", colorama.Fore.WHITE)
        print_colored(f"Total SLOs: {summary.total_slos}", colorama.Fore.WHITE)
        print_colored(f"Total SLO Units: {summary.total_slo_units}", colorama.Fore.WHITE)
        print_colored(f"Total Composite SLOs: {summary.total_composite_slos}", colorama.Fore.WHITE)
        print_colored(f"Total Composite Components: {summary.total_composite_components}", colorama.Fore.WHITE)
        print_colored(f"Total Services: {summary.total_services}", colorama.Fore.WHITE)
        print_colored(f"Total Alert Policies: {summary.total_alert_policies}", colorama.Fore.WHITE)
        print_colored(f"Total Data Sources: {summary.total_data_sources}", colorama.Fore.WHITE)
        print_colored(f"Total Users: {summary.total_users}", colorama.Fore.WHITE)
        coverage_color = colorama.Fore.GREEN if summary.slo_coverage > 50 else colorama.Fore.YELLOW if summary.slo_coverage > 25 else colorama.Fore.YELLOW
        print_colored(f"Alert Coverage: {summary.slo_coverage:.1f}%", coverage_color)
        print_colored(f"Last 7 Days Changes: {summary.last_7_days_changes}", colorama.Fore.WHITE)
        
        # Top Active Users
        if summary.top_active_users:
            print()
            print_header("TOP 10 MOST ACTIVE USERS")
            for i, (user, count) in enumerate(summary.top_active_users, 1):
                user_display = user if user != "System" else "System"
                print_colored(f"{i}. {user_display} ({count} changes)", colorama.Fore.WHITE)
        print()
        
        # Project Matrix
        print_header("PROJECT MATRIX")
        print_colored(f"{'Project Name':<30} {'SLOs':<6} {'Services':<8} {'Alert Policies':<15}", colorama.Fore.WHITE)
        print_colored("-" * 65, colorama.Fore.CYAN)
        
        for project in sorted(self.projects, key=lambda x: x.slo_count, reverse=True):
            print(f"{project.name:<30} {project.slo_count:<6} {project.service_count:<8} {project.alert_policy_count:<15}")
        print()
        
        # Projects with no services
        projects_without_services = [p for p in self.projects if p.service_count == 0]
        if projects_without_services:
            print_header("PROJECTS WITH NO SERVICES")
            for i, project in enumerate(projects_without_services):
                if i < 25:
                    print_colored(f"  • {project.name} ({project.slo_count} SLOs, {project.alert_policy_count} Alert Policies)", colorama.Fore.YELLOW)
                else:
                    break
            if len(projects_without_services) > 25:
                print_colored(f"  ... and {len(projects_without_services) - 25} more projects with no services", colorama.Fore.YELLOW)
            print()
        
        # Projects with no SLOs
        projects_without_slos = [p for p in self.projects if p.slo_count == 0]
        if projects_without_slos:
            print_header("PROJECTS WITH NO SLOs")
            for i, project in enumerate(projects_without_slos):
                if i < 25:
                    print_colored(f"  • {project.name} ({project.service_count} Services, {project.alert_policy_count} Alert Policies)", colorama.Fore.YELLOW)
                else:
                    break
            if len(projects_without_slos) > 25:
                print_colored(f"  ... and {len(projects_without_slos) - 25} more projects with no SLOs", colorama.Fore.YELLOW)
            print()
        
        # Composite SLO Analysis
        if self.composite_slos:
            print_header("COMPOSITE SLO ANALYSIS")
            print_colored(f"Total Composite SLOs: {len(self.composite_slos)}", colorama.Fore.WHITE)
            print_colored(f"Total Composite Components: {sum(slo.component_count for slo in self.composite_slos)}", colorama.Fore.WHITE)
            print()
            
            # Composite SLOs by component count
            print_header("COMPOSITE SLOs BY COMPONENT COUNT")
            print_colored(f"{'Name':<50} {'Project':<20} {'Components':<12} {'Target':<10}", colorama.Fore.WHITE)
            print_colored("-" * 95, colorama.Fore.CYAN)
            
            for slo in sorted(self.composite_slos, key=lambda x: x.component_count, reverse=True):
                target_str = f"{slo.target:.6f}" if slo.target else "N/A"
                # Truncate long names and add ellipsis if needed
                display_name = slo.name
                if len(display_name) > 48:
                    display_name = display_name[:45] + "..."
                print(f"{display_name:<50} {slo.project:<20} {slo.component_count:<12} {target_str:<10}")
            print()
            
            # Detailed breakdown
            print_header("DETAILED COMPOSITE SLO BREAKDOWN")
            for slo in sorted(self.composite_slos, key=lambda x: x.component_count, reverse=True):
                print_colored(f"• {slo.name} ({slo.project}) - {slo.component_count} components", colorama.Fore.CYAN)
                if slo.description:
                    # Clean up description: remove line breaks, extra spaces, and special characters
                    clean_description = slo.description.replace('\n', ' ').replace('\r', ' ').replace('•••', '...')
                    # Remove multiple consecutive spaces
                    clean_description = re.sub(r'\s+', ' ', clean_description).strip()
                    print_colored(f"  Description: {clean_description}", colorama.Fore.WHITE)
                
                # Show component details in a table format
                print_colored(f"  Components:", colorama.Fore.WHITE)
                print_colored(f"    {'Name':<75} {'Weight':<10} {'Norm Weight':<12} {'When Delayed':<15} {'Composite Target':<18}", colorama.Fore.CYAN)
                print_colored(f"    {'-' * 75} {'-' * 10} {'-' * 12} {'-' * 15} {'-' * 18}", colorama.Fore.CYAN)
                for comp in slo.components:
                    when_delayed_str = comp.when_delayed if comp.when_delayed else "N/A"
                    weight_str = f"{comp.weight:.2f}" if comp.weight else "N/A"
                    norm_weight_str = f"{comp.normalized_weight:.2f}" if comp.normalized_weight else "N/A"
                    composite_target_str = f"{slo.target:.6f}" if slo.target else "N/A"
                    
                    # Truncate long names and add ellipsis if needed
                    display_name = comp.name
                    if len(display_name) > 73:
                        display_name = display_name[:70] + "..."
                    
                    # Print component data with composite target in grey
                    print_colored(f"    {display_name:<75} {weight_str:<10} {norm_weight_str:<12} {when_delayed_str:<15} ", colorama.Fore.WHITE, end="")
                    print_colored(f"{composite_target_str:<18}", colorama.Fore.LIGHTBLACK_EX)
                
                if slo.alert_policies:
                    print_colored(f"  Alert Policies: {', '.join(slo.alert_policies)}", colorama.Fore.WHITE)
                print()
        else:
            print_header("COMPOSITE SLO ANALYSIS")
            print_colored("No composite SLOs found in this account.", colorama.Fore.YELLOW)
            print()
        
        # Alert Coverage Analysis
        print_header("ALERT COVERAGE ANALYSIS")
        slos_with_policies = len([slo for slo in self.slos if slo.alert_policies])
        slos_without_policies = len([slo for slo in self.slos if not slo.alert_policies])
        
        print_colored(f"SLOs with Alert Policies: {slos_with_policies} ({summary.slo_coverage:.1f}%)", colorama.Fore.WHITE)
        print_colored(f"SLOs without Alert Policies: {slos_without_policies} ({100-summary.slo_coverage:.1f}%)", colorama.Fore.RED)
        print()
        
        if slos_without_policies > 0:
            print_colored("SLOs without Alert Policies:", colorama.Fore.YELLOW)
            uncovered_count = 0
            for slo in self.slos:
                if not slo.alert_policies:
                    if uncovered_count < 25:
                        print_colored(f"  • {slo.service}/{slo.name} (project: {slo.project})", colorama.Fore.WHITE)
                        uncovered_count += 1
                    else:
                        break
            if slos_without_policies > 25:
                print_colored(f"  ... and {slos_without_policies - 25} more SLOs without alert policies", colorama.Fore.YELLOW)
            print()
        
        # Alert Policy Effectiveness
        print_header("ALERT POLICY EFFECTIVENESS")
        if self.alert_policies:
            most_used = max(self.alert_policies, key=lambda x: x.used_by_slos)
            unused_policies = [p for p in self.alert_policies if p.used_by_slos == 0]
            
            print_colored(f"Most Used Policy: '{most_used.name}' (used by {most_used.used_by_slos} SLOs)", colorama.Fore.GREEN)
            if unused_policies:
                print_colored(f"Unused Alert Policies ({len(unused_policies)}):", colorama.Fore.RED)
                for i, policy in enumerate(unused_policies):
                    if i < 25:
                        print_colored(f"  • {policy.name} (project: {policy.project})", colorama.Fore.WHITE)
                    else:
                        break
                if len(unused_policies) > 25:
                    print_colored(f"  ... and {len(unused_policies) - 25} more unused alert policies", colorama.Fore.YELLOW)
            print()
        
        # Service Analysis
        print_header("SERVICE ANALYSIS")
        if self.services:
            # Services by SLO count
            services_by_slo_count = sorted(self.services, key=lambda x: x.slo_count, reverse=True)
            print_header("TOP SERVICES BY SLO COUNT")
            for i, service in enumerate(services_by_slo_count[:10], 1):
                print(f"  {i:2d}. {service.name:<25} ({service.project}) - {service.slo_count} SLOs")
            print()
            
            # Service coverage analysis
            services_with_slos = len([s for s in self.services if s.slo_count > 0])
            services_without_slos = len([s for s in self.services if s.slo_count == 0])
            print_header("SERVICE COVERAGE")
            print(f"Services with SLOs: {services_with_slos}")
            if services_without_slos > 0:
                print(f"Services without SLOs ({services_without_slos}):")
                for service in [s for s in self.services if s.slo_count == 0]:
                    print(f"  • {service.name} (project: {service.project})")
            print()
        
        # Data Source Analysis
        print_header("DATA SOURCE ANALYSIS")
        
        # Get all data sources to map names to types
        agents = self._get_data_sources("agents")
        directs = self._get_data_sources("directs")
        all_data_sources = {**agents, **directs}
        
        # Create a comprehensive mapping of ALL configured data sources (including unused ones)
        source_analysis = {}
        
        # First, add all configured agents and directs with 0 SLOs
        for source_name, source_type in all_data_sources.items():
            source_analysis[source_name] = {
                'type': source_type,
                'kind': 'Agent' if source_name in agents else 'Direct',
                'slo_count': 0,
                'found_in_config': True,
                'configured': True
            }
        
        # Manually count SLOs for data sources
        for slo in self.slos:
            raw_slo_data = self._slo_lookup.get((slo.name, slo.project))
            
            if not raw_slo_data:
                # Find raw SLO data manually if lookup not available
                for raw_slo in self.raw_slo_data:
                    if (raw_slo.get("metadata", {}).get("name") == slo.name and 
                        raw_slo.get("metadata", {}).get("project") == slo.project):
                        raw_slo_data = raw_slo
                        break
            
            if raw_slo_data:
                spec = raw_slo_data.get("spec", {})
                indicator = spec.get("indicator", {})
                
                if "composite" not in indicator:
                    metric_source = indicator.get("metricSource", {})
                    source_name = metric_source.get("name", "")
                    source_kind = metric_source.get("kind", "Unknown")
                    
                    if source_name:
                        if source_name not in source_analysis:
                            # This data source is used by SLOs but not found in config
                            source_analysis[source_name] = {
                                'type': 'Unknown',
                                'kind': source_kind,
                                'slo_count': 0,
                                'found_in_config': False,
                                'configured': False
                            }
                        
                        source_analysis[source_name]['slo_count'] += 1
        
        # Display data source types in a table format
        if source_analysis:
            print_colored(f"{'Data Source Name':<35} {'Source':<15} {'Kind':<10} {'SLOs':<10} {'Status':<10}", colorama.Fore.CYAN)
            print_colored("-" * 85, colorama.Fore.CYAN)
            for source_name in sorted(source_analysis.keys()):
                info = source_analysis[source_name]
                source_type = info['type']
                kind = info['kind']
                slo_count = info['slo_count']
                
                # Status: ✓ for configured and used, ⚠ for configured but unused, ❌ for used but not configured
                if info['configured'] and info['slo_count'] > 0:
                    status = "✓"
                elif info['configured'] and info['slo_count'] == 0:
                    status = "⚠"
                else:
                    status = "❌"
                
                print_colored(f"{source_name:<35} {source_type:<15} {kind:<10} {slo_count:<10} {status:<10}", colorama.Fore.WHITE)
            print()
            
            # Summary of different data source states
            configured_unused = [name for name, info in source_analysis.items() if info['configured'] and info['slo_count'] == 0]
            used_unconfigured = [name for name, info in source_analysis.items() if not info['configured'] and info['slo_count'] > 0]
            
            if configured_unused:
                print_header("CONFIGURED BUT UNUSED DATA SOURCES")
                for source in configured_unused:
                    print_colored(f"  • {source}", colorama.Fore.YELLOW)
                print()
            
            if used_unconfigured:
                print_header("USED BUT UNCONFIGURED DATA SOURCES")
                for source in used_unconfigured:
                    print_colored(f"  • {source}", colorama.Fore.RED)
                print()
        print()
        
        # SLO Objective Analysis
        print_header("TIME WINDOW ANALYSIS")
        if self.slos:
            # Detailed time window analysis
            time_window_details = {}
            calendar_aligned = 0
            rolling_windows = 0
            
            for slo in self.slos:
                # Get the raw SLO data to access detailed time window info
                raw_slo_data = None
                for raw_slo in self.raw_slo_data:
                    if (raw_slo.get("metadata", {}).get("name") == slo.name and 
                        raw_slo.get("metadata", {}).get("project") == slo.project):
                        raw_slo_data = raw_slo
                        break
                
                if raw_slo_data:
                    spec = raw_slo_data.get("spec", {})
                    time_windows = spec.get("timeWindows", [])
                    
                    for tw in time_windows:
                        # Check if rolling or calendar-aligned
                        is_rolling = tw.get("isRolling", False)
                        if is_rolling:
                            rolling_windows += 1
                        else:
                            calendar_aligned += 1
                        
                        # Get duration details
                        count = tw.get("count", 0)
                        unit = tw.get("unit", "Unknown")
                        
                        # Create detailed key
                        if count > 0:
                            key = f"{count} {unit}"
                            if is_rolling:
                                key += " (Rolling)"
                            else:
                                key += " (Calendar)"
                            
                            time_window_details[key] = time_window_details.get(key, 0) + 1
                        else:
                            # Handle cases where count might be 0 or missing
                            time_window_details[f"Unknown {unit}"] = time_window_details.get(f"Unknown {unit}", 0) + 1
            
            # Display time window analysis
            if time_window_details:
                print_colored("Time Window Distribution:", colorama.Fore.WHITE)
                for window, count in sorted(time_window_details.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / len(self.slos)) * 100
                    print_colored(f"  • {window}: {count} SLOs ({percentage:.1f}%)", colorama.Fore.WHITE)
                
                print()
                print_colored("Time Window Types:", colorama.Fore.WHITE)
                rolling_percentage = (rolling_windows / len(self.slos)) * 100 if self.slos else 0
                calendar_percentage = (calendar_aligned / len(self.slos)) * 100 if self.slos else 0
                print_colored(f"  • Rolling Windows: {rolling_windows} SLOs ({rolling_percentage:.1f}%)", colorama.Fore.WHITE)
                print_colored(f"  • Calendar Aligned: {calendar_aligned} SLOs ({calendar_percentage:.1f}%)", colorama.Fore.WHITE)
            print()
        
        # Recent SLO Changes
        print_header("RECENT SLO CHANGES")
        
        # Get all SLOs with update timestamps and sort by most recent
        slos_with_updates = [slo for slo in self.slos if slo.updated_at]
        slos_with_updates.sort(key=lambda x: x.updated_at, reverse=True)
        
        if slos_with_updates:
            print_colored(f"20 Most Recently Updated SLOs:", colorama.Fore.WHITE)
            print()
            
            # Create a table header
            print_colored(f"{'Display Name':<35} {'Project':<20} {'Last Updated':<25}", colorama.Fore.CYAN)
            print_colored("-" * 80, colorama.Fore.CYAN)
            
            # Show the 20 most recent with display names
            for slo in slos_with_updates[:20]:
                # Get display name from raw SLO data
                display_name = slo.name  # Default to name if no display name
                for raw_slo in self.raw_slo_data:
                    if (raw_slo.get("metadata", {}).get("name") == slo.name and 
                        raw_slo.get("metadata", {}).get("project") == slo.project):
                        display_name = raw_slo.get("metadata", {}).get("displayName", slo.name)
                        break
                
                # Format the timestamp for better readability
                try:
                    timestamp = datetime.fromisoformat(slo.updated_at.replace("Z", "+00:00"))
                    formatted_time = timestamp.strftime("%Y-%m-%d %H:%M")
                except ValueError:
                    formatted_time = slo.updated_at
                
                print_colored(f"{display_name:<35} {slo.project:<20} {formatted_time:<25}", colorama.Fore.WHITE)
        else:
            print_colored("No SLOs with update timestamps found", colorama.Fore.YELLOW)
        
        print()
        
        # Audit Trail Summary
        if self.audit_logs:
            print_header("AUDIT TRAIL SUMMARY (Last 7 Days)")
            
            event_types = {}
            for log in self.audit_logs:
                event = log.event
                event_types[event] = event_types.get(event, 0) + 1
            
            print("Change Breakdown:")
            for event, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  • {event}: {count}")
            print()
        
        print("="*60)
        print("Report generation complete!")
        print("="*60)
        
        # Offer export options
        self._offer_export_options(summary)
    
    def _export_csv(self, summary: AccountSummary):
        """Export data to CSV format with comprehensive sections"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nobl9_account_analysis_{self.context_name}_{timestamp}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
            
            # Summary section
            writer.writerow(["Nobl9 Account Analysis Summary"])
            writer.writerow(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(["Organization", self.organization_id])
            writer.writerow([])
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Total Projects", summary.total_projects])
            writer.writerow(["Total SLOs", summary.total_slos])
            writer.writerow(["Total SLO Units", summary.total_slo_units])
            writer.writerow(["Total Composite SLOs", summary.total_composite_slos])
            writer.writerow(["Total Composite Components", summary.total_composite_components])
            writer.writerow(["Total Services", summary.total_services])
            writer.writerow(["Total Alert Policies", summary.total_alert_policies])
            writer.writerow(["Total Data Sources", summary.total_data_sources])
            writer.writerow(["Total Users", summary.total_users])
            writer.writerow(["Alert Coverage", f"{summary.slo_coverage:.1f}%"])
            writer.writerow(["Last 7 Days Changes", summary.last_7_days_changes])
            
            # Projects section
            writer.writerow([])
            writer.writerow(["PROJECTS"])
            writer.writerow(["Name", "Display Name", "Description", "SLOs", "Services", "Alert Policies"])
            for project in self.projects:
                writer.writerow([
                    project.name, project.display_name, project.description,
                    project.slo_count, project.service_count, project.alert_policy_count
                ])
            
            # SLOs section
            writer.writerow([])
            writer.writerow(["SLOS"])
            writer.writerow(["Name", "Project", "Service", "Description", "Target", "Alert Policies", "Health"])
            for slo in self.slos:
                if slo.alert_policies:
                    # Create a row for each alert policy
                    for policy in slo.alert_policies:
                        writer.writerow([
                            slo.name, slo.project, slo.service, slo.description,
                            slo.target, policy, slo.health_status
                        ])
                else:
                    # SLO with no alert policies
                    writer.writerow([
                        slo.name, slo.project, slo.service, slo.description,
                        slo.target, "None", slo.health_status
                    ])
            
            # Composite SLOs section
            if self.composite_slos:
                writer.writerow([])
                writer.writerow(["COMPOSITE SLOS"])
                writer.writerow(["Name", "Project", "Description", "Component Count", "Target", "Alert Policies", "Health"])
                for slo in self.composite_slos:
                    alert_policies_str = ", ".join(slo.alert_policies) if slo.alert_policies else "None"
                    writer.writerow([
                        slo.name, slo.project, slo.description, slo.component_count,
                        slo.target, alert_policies_str, slo.health_status
                    ])
                
                # Component details section
                writer.writerow([])
                writer.writerow(["COMPOSITE SLO COMPONENTS"])
                writer.writerow(["Composite SLO", "Project", "Component Name", "Weight", "Normalized Weight", "When Delayed", "Composite Target"])
                for slo in self.composite_slos:
                    for comp in slo.components:
                        when_delayed_str = comp.when_delayed if comp.when_delayed else "N/A"
                        composite_target = slo.target if slo.target is not None else "N/A"
                        writer.writerow([
                            slo.name, slo.project, comp.name, comp.weight, comp.normalized_weight, when_delayed_str, composite_target
                        ])
            
            # Alert Policies section
            writer.writerow([])
            writer.writerow(["ALERT POLICIES"])
            writer.writerow(["Name", "Project", "Description", "Severity", "Used by SLOs"])
            for policy in self.alert_policies:
                writer.writerow([
                    policy.name, policy.project, policy.description,
                    policy.severity, policy.used_by_slos
                ])
            
            # Services section
            writer.writerow([])
            writer.writerow(["SERVICES"])
            writer.writerow(["Name", "Project", "Description", "SLO Count"])
            for service in self.services:
                writer.writerow([
                    service.name, service.project, service.description, service.slo_count
                ])
            
            # SLOs without Alert Policies section
            slos_without_policies = [slo for slo in self.slos if not slo.alert_policies]
            if slos_without_policies:
                writer.writerow([])
                writer.writerow(["SLOS WITHOUT ALERT POLICIES"])
                writer.writerow(["Service", "SLO Name", "Project", "Description", "Target"])
                for slo in slos_without_policies:
                    writer.writerow([
                        slo.service, slo.name, slo.project, slo.description,
                        slo.target
                    ])
            
            # Unused Alert Policies section
            unused_policies = [p for p in self.alert_policies if p.used_by_slos == 0]
            if unused_policies:
                writer.writerow([])
                writer.writerow(["UNUSED ALERT POLICIES"])
                writer.writerow(["Name", "Project", "Description", "Severity"])
                for policy in unused_policies:
                    writer.writerow([
                        policy.name, policy.project, policy.description, policy.severity
                    ])
            
            # Top Services by SLO Count section
            if self.services:
                writer.writerow([])
                writer.writerow(["TOP SERVICES BY SLO COUNT"])
                writer.writerow(["Rank", "Service Name", "Project", "SLO Count", "Description"])
                services_by_slo_count = sorted(self.services, key=lambda x: x.slo_count, reverse=True)
                for i, service in enumerate(services_by_slo_count[:20], 1):
                    writer.writerow([
                        i, service.name, service.project, service.slo_count, service.description
                    ])
            
            # Recent SLO Changes section
            slos_with_updates = [slo for slo in self.slos if slo.updated_at]
            if slos_with_updates:
                writer.writerow([])
                writer.writerow(["RECENT SLO CHANGES"])
                writer.writerow(["Display Name", "SLO Name", "Project", "Service", "Last Updated"])
                slos_with_updates.sort(key=lambda x: x.updated_at, reverse=True)
                for slo in slos_with_updates:
                    # Get display name from raw SLO data
                    display_name = slo.name
                    for raw_slo in self.raw_slo_data:
                        if (raw_slo.get("metadata", {}).get("name") == slo.name and 
                            raw_slo.get("metadata", {}).get("project") == slo.project):
                            display_name = raw_slo.get("metadata", {}).get("displayName", slo.name)
                            break
                    
                    writer.writerow([
                        display_name, slo.name, slo.project, slo.service,
                        slo.updated_at
                    ])
            
            # Top 10 Most Active Users section
            if summary.top_active_users:
                writer.writerow([])
                writer.writerow(["TOP 10 MOST ACTIVE USERS"])
                writer.writerow(["Rank", "User", "Change Count"])
                for i, (user, count) in enumerate(summary.top_active_users, 1):
                    writer.writerow([i, user, count])
            
            # User Activity section (if audit logs available)
            if summary.top_active_users:
                writer.writerow([])
                writer.writerow(["USER ACTIVITY"])
                writer.writerow(["User", "Change Count", "Percentage"])
                
                total_changes = summary.last_7_days_changes
                for user, count in summary.top_active_users:
                    percentage = (count / total_changes) * 100 if total_changes > 0 else 0
                    writer.writerow([user, count, f"{percentage:.1f}%"])
            
        except Exception as e:
            print(f"Error during CSV export: {e}")
            print(f"Attempted to export to: {filename}")
            return
        
        print(f"CSV report exported to: {filename}")
    
    def _export_json(self, summary: AccountSummary):
        """Export data to JSON format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nobl9_account_analysis_{self.context_name}_{timestamp}.json"
        
        export_data = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "organization": self.organization_id,
                "version": "1.0.0"
            },
            "summary": asdict(summary),
            "projects": [asdict(p) for p in self.projects],
            "slos": [asdict(s) for s in self.slos],
            "composite_slos": [asdict(s) for s in self.composite_slos],
            "composite_slo_components": [
                {**asdict(comp), "composite_target": slo.target} 
                for slo in self.composite_slos for comp in slo.components
            ],
            "alert_policies": [asdict(a) for a in self.alert_policies],
            "services": [asdict(s) for s in self.services],
            "audit_logs": [asdict(a) for a in self.audit_logs]
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error during JSON export: {e}")
            print(f"Attempted to export to: {filename}")
            return
        
        print(f"JSON report exported to: {filename}")
    
    def _auto_adjust_column_widths(self, writer, sheet_name, dataframe):
        """Auto-adjust column widths for an Excel sheet"""
        worksheet = writer.sheets[sheet_name]
        for idx, col in enumerate(dataframe.columns):
            max_length = max(
                dataframe[col].astype(str).apply(len).max(),
                len(col)
            )
            worksheet.column_dimensions[chr(65 + idx)].width = min(max_length + 2, 50)

    def _export_excel(self, summary: AccountSummary):
        """Export data to Excel format with comprehensive tabs"""
        try:
            import pandas as pd
            import openpyxl
        except ImportError:
            print("Excel export requires pandas and openpyxl. Install with: pip install pandas openpyxl")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nobl9_account_analysis_{self.context_name}_{timestamp}.xlsx"
        
        try:
            # Create Excel writer
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                # Summary sheet
                summary_data = {
                    'Metric': ['Generated', 'Organization', 'Total Projects', 'Total SLOs', 'Total SLO Units', 'Total Composite SLOs', 'Total Composite Components', 'Total Services', 
                              'Total Alert Policies', 'Total Data Sources', 'Total Users', 'Alert Coverage', 'Last 7 Days Changes'],
                    'Value': [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.organization_id,
                             summary.total_projects, summary.total_slos, summary.total_slo_units, summary.total_composite_slos, summary.total_composite_components, summary.total_services,
                             summary.total_alert_policies, summary.total_data_sources, summary.total_users,
                             f"{summary.slo_coverage:.1f}%", summary.last_7_days_changes]
                }
                summary_df = pd.DataFrame(summary_data)
                # Clean up empty/None values to prevent empty columns
                summary_df = summary_df.replace(['', 'None', 'NaN', 'nan'], pd.NA).dropna(axis=1, how='all')
                # Ensure we only have the expected columns
                summary_df = summary_df[['Metric', 'Value']]
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
                self._auto_adjust_column_widths(writer, 'Summary', summary_df)
                
                # Projects sheet
                projects_data = []
                for project in self.projects:
                    projects_data.append({
                        'Name': project.name,
                        'Display Name': project.display_name,
                        'Description': project.description,
                        'SLOs': project.slo_count,
                        'Services': project.service_count,
                        'Alert Policies': project.alert_policy_count,
                        'Created At': project.created_at
                    })
                projects_df = pd.DataFrame(projects_data)
                # Clean up empty/None values to prevent empty columns
                projects_df = projects_df.replace(['', 'None'], pd.NA).dropna(axis=1, how='all')
                projects_df.to_excel(writer, sheet_name='Projects', index=False)
                self._auto_adjust_column_widths(writer, 'Projects', projects_df)
                
                # SLOs sheet
                slos_data = []
                for slo in self.slos:
                    if slo.alert_policies:
                        # Create a row for each alert policy
                        for policy in slo.alert_policies:
                            slos_data.append({
                                'Name': slo.name,
                                'Project': slo.project,
                                'Service': slo.service,
                                'Description': slo.description,
                                'Target': slo.target,
                                'Time Window': slo.time_window,
                                'Alert Policy': policy,
                                'Health Status': slo.health_status,
                                'Created At': slo.created_at,
                                'Updated At': slo.updated_at
                            })
                    else:
                        # SLO with no alert policies
                        slos_data.append({
                            'Name': slo.name,
                            'Project': slo.project,
                            'Service': slo.service,
                            'Description': slo.description,
                            'Target': slo.target,
                            'Time Window': slo.time_window,
                            'Alert Policy': 'None',
                            'Health Status': slo.health_status,
                            'Created At': slo.created_at,
                            'Updated At': slo.updated_at
                        })
                
                slos_df = pd.DataFrame(slos_data)
                # Clean up empty/None values to prevent empty columns
                slos_df = slos_df.replace(['', 'None', '[]', 'unknown'], pd.NA).dropna(axis=1, how='all')
                slos_df.to_excel(writer, sheet_name='SLOs', index=False)
                self._auto_adjust_column_widths(writer, 'SLOs', slos_df)
                
                # Composite SLOs sheet
                if self.composite_slos:
                    composite_slos_data = []
                    for slo in self.composite_slos:
                        alert_policies_str = ", ".join(slo.alert_policies) if slo.alert_policies else "None"
                        composite_slos_data.append({
                            'Name': slo.name,
                            'Project': slo.project,
                            'Description': slo.description,
                            'Component Count': slo.component_count,
                            'Target': slo.target,
                            'Time Window': slo.time_window,
                            'Alert Policies': alert_policies_str,
                            'Health Status': slo.health_status,
                            'Created At': slo.created_at,
                            'Updated At': slo.updated_at
                        })
                    
                    composite_slos_df = pd.DataFrame(composite_slos_data)
                    # Clean up empty/None values to prevent empty columns
                    composite_slos_df = composite_slos_df.replace(['', 'None', '[]', 'unknown'], pd.NA).dropna(axis=1, how='all')
                    composite_slos_df.to_excel(writer, sheet_name='Composite SLOs', index=False)
                    self._auto_adjust_column_widths(writer, 'Composite SLOs', composite_slos_df)
                    
                    # Composite SLO Components sheet
                    components_data = []
                    for slo in self.composite_slos:
                        for comp in slo.components:
                            when_delayed_str = comp.when_delayed if comp.when_delayed else "N/A"
                            components_data.append({
                                'Composite SLO': slo.name,
                                'Project': slo.project,
                                'Component Name': comp.name,
                                'Weight': comp.weight,
                                'Normalized Weight': comp.normalized_weight,
                                'When Delayed': when_delayed_str,
                                'Composite Target': slo.target if slo.target is not None else "N/A"
                            })
                    
                    components_df = pd.DataFrame(components_data)
                    # Clean up empty/None values to prevent empty columns
                    components_df = components_df.replace(['', 'None', '[]', 'unknown'], pd.NA).dropna(axis=1, how='all')
                    components_df.to_excel(writer, sheet_name='Composite SLO Components', index=False)
                    self._auto_adjust_column_widths(writer, 'Composite SLO Components', components_df)
                else:
                    pass
        
                # Alert Policies sheet
                policies_data = []
                for policy in self.alert_policies:
                    policies_data.append({
                        'Name': policy.name,
                        'Project': policy.project,
                        'Description': policy.description,
                        'Severity': policy.severity,
                        'Used by SLOs': policy.used_by_slos
                    })
                policies_df = pd.DataFrame(policies_data)
                policies_df.to_excel(writer, sheet_name='Alert Policies', index=False)
                self._auto_adjust_column_widths(writer, 'Alert Policies', policies_df)
                
                # Services sheet
                services_data = []
                for service in self.services:
                    services_data.append({
                        'Name': service.name,
                        'Project': service.project,
                        'Description': service.description,
                        'SLO Count': service.slo_count
                    })
                services_df = pd.DataFrame(services_data)
                # Clean up empty/None values to prevent empty columns
                services_df = services_df.replace(['', 'None'], pd.NA).dropna(axis=1, how='all')
                services_df.to_excel(writer, sheet_name='Services', index=False)
                self._auto_adjust_column_widths(writer, 'Services', services_df)
                
                # SLOs without Alert Policies section
                slos_without_policies = [slo for slo in self.slos if not slo.alert_policies]
                if slos_without_policies:
                    uncovered_slos_data = []
                    for slo in slos_without_policies:
                        uncovered_slos_data.append({
                            'Service': slo.service,
                            'SLO Name': slo.name,
                            'Project': slo.project,
                            'Description': slo.description
                        })
                    uncovered_df = pd.DataFrame(uncovered_slos_data)
                    uncovered_df.to_excel(writer, sheet_name='SLOs without Alert Policies', index=False)
                    self._auto_adjust_column_widths(writer, 'SLOs without Alert Policies', uncovered_df)
                else:
                    pass
                
                # Unused Alert Policies section
                unused_policies = [p for p in self.alert_policies if p.used_by_slos == 0]
                if unused_policies:
                    unused_policies_data = []
                    for policy in unused_policies:
                        unused_policies_data.append({
                            'Name': policy.name,
                            'Project': policy.project,
                            'Description': policy.description,
                            'Severity': policy.severity
                        })
                    unused_df = pd.DataFrame(unused_policies_data)
                    unused_df.to_excel(writer, sheet_name='Unused Alert Policies', index=False)
                    self._auto_adjust_column_widths(writer, 'Unused Alert Policies', unused_df)
                else:
                    pass
                
                # Top Services by SLO Count section
                if self.services:
                    services_by_slo_count = sorted(self.services, key=lambda x: x.slo_count, reverse=True)
                    top_services_data = []
                    for i, service in enumerate(services_by_slo_count[:20], 1):  # Top 20
                        top_services_data.append({
                            'Rank': i,
                            'Service Name': service.name,
                            'Project': service.project,
                            'SLO Count': service.slo_count,
                            'Description': service.description
                        })
                    top_services_df = pd.DataFrame(top_services_data)
                    top_services_df.to_excel(writer, sheet_name='Top Services by SLO Count', index=False)
                    self._auto_adjust_column_widths(writer, 'Top Services by SLO Count', top_services_df)
                else:
                    pass
                
                # Data Source Analysis sheet
                if hasattr(self, '_slo_lookup') and self._slo_lookup:
                    # Get all data sources
                    agents = self._get_data_sources("agents")
                directs = self._get_data_sources("directs")
                all_data_sources = {**agents, **directs}
                
                # Create comprehensive data source analysis
                source_analysis = {}
                
                # First, add all configured agents and directs
                for source_name, source_type in all_data_sources.items():
                    source_analysis[source_name] = {
                        'Data Source Name': source_name,
                        'Source Type': source_type,
                        'Kind': 'Agent' if source_name in agents else 'Direct',
                        'SLO Count': 0,
                        'Configured': 'Yes',
                        'Status': 'Unused'
                    }
                
                # Count SLOs for each data source
                for slo in self.slos:
                    raw_slo_data = self._slo_lookup.get((slo.name, slo.project))
                    if raw_slo_data:
                        spec = raw_slo_data.get("spec", {})
                        indicator = spec.get("indicator", {})
                        
                        if "composite" not in indicator:
                            metric_source = indicator.get("metricSource", {})
                            source_name = metric_source.get("name", "")
                            source_kind = metric_source.get("kind", "Unknown")
                            
                            if source_name:
                                if source_name not in source_analysis:
                                    source_analysis[source_name] = {
                                        'Data Source Name': source_name,
                                        'Source Type': 'Unknown',
                                        'Kind': source_kind,
                                        'SLO Count': 0,
                                        'Configured': 'No',
                                        'Status': 'Used but Unconfigured'
                                    }
                                
                                source_analysis[source_name]['SLO Count'] += 1
                                if source_analysis[source_name]['Configured'] == 'Yes':
                                    source_analysis[source_name]['Status'] = 'Active'
                
                # Convert to DataFrame
                if source_analysis:
                    source_analysis_data = list(source_analysis.values())
                    source_df = pd.DataFrame(source_analysis_data)
                    source_df.to_excel(writer, sheet_name='Data Source Analysis', index=False)
                    self._auto_adjust_column_widths(writer, 'Data Source Analysis', source_df)
                else:
                    pass
            
            # Time Window Analysis sheet
            if self.slos:
                time_window_details = {}
                calendar_aligned = 0
                rolling_windows = 0
                
                for slo in self.slos:
                    raw_slo_data = None
                    for raw_slo in self.raw_slo_data:
                        if (raw_slo.get("metadata", {}).get("name") == slo.name and 
                            raw_slo.get("metadata", {}).get("project") == slo.project):
                            raw_slo_data = raw_slo
                            break
                    
                    if raw_slo_data:
                        spec = raw_slo_data.get("spec", {})
                        time_windows = spec.get("timeWindows", [])
                        
                        for tw in time_windows:
                            is_rolling = tw.get("isRolling", False)
                            if is_rolling:
                                rolling_windows += 1
                            else:
                                calendar_aligned += 1
                            
                            count = tw.get("count", 0)
                            unit = tw.get("unit", "Unknown")
                            
                            if count > 0:
                                key = f"{count} {unit}"
                                if is_rolling:
                                    key += " (Rolling)"
                                else:
                                    key += " (Calendar)"
                                
                                time_window_details[key] = time_window_details.get(key, 0) + 1
                
                if time_window_details:
                    time_window_data = []
                    for window, count in sorted(time_window_details.items(), key=lambda x: x[1], reverse=True):
                        percentage = (count / len(self.slos)) * 100
                        time_window_data.append({
                            'Time Window': window,
                            'SLO Count': count,
                            'Percentage': f"{percentage:.1f}%"
                        })
                    
                    # Add summary rows
                    time_window_data.append({
                        'Time Window': 'Rolling Windows Total',
                        'SLO Count': rolling_windows,
                        'Percentage': f"{(rolling_windows / len(self.slos)) * 100:.1f}%"
                    })
                    time_window_data.append({
                        'Time Window': 'Calendar Aligned Total',
                        'SLO Count': calendar_aligned,
                        'Percentage': f"{(calendar_aligned / len(self.slos)) * 100:.1f}%"
                    })
                    
                    time_window_df = pd.DataFrame(time_window_data)
                    time_window_df.to_excel(writer, sheet_name='Time Window Analysis', index=False)
                    self._auto_adjust_column_widths(writer, 'Time Window Analysis', time_window_df)
                else:
                    pass
            
            # Recent SLO Changes sheet
            slos_with_updates = [slo for slo in self.slos if slo.updated_at]
            if slos_with_updates:
                slos_with_updates.sort(key=lambda x: x.updated_at, reverse=True)
                recent_changes_data = []
                
                for slo in slos_with_updates:  # Full list for export
                    # Get display name from raw SLO data
                    display_name = slo.name
                    for raw_slo in self.raw_slo_data:
                        if (raw_slo.get("metadata", {}).get("name") == slo.name and 
                            raw_slo.get("metadata", {}).get("project") == slo.project):
                            display_name = raw_slo.get("metadata", {}).get("displayName", slo.name)
                            break
                    
                    # Find who made the change from audit logs
                    changed_by = "Unknown"
                    for log in self.audit_logs:
                        # Look for SLO-related events in audit logs
                        if (log.object_type == "SLO" and 
                            log.object_name == slo.name and 
                            log.project == slo.project):
                            # Parse user information from actor field
                            actor = log.actor
                            if actor and "user" in actor and actor["user"]:
                                user_info = actor["user"]
                                if "firstName" in user_info and "lastName" in user_info:
                                    changed_by = (f"{user_info['firstName'].strip()} "
                                               f"{user_info['lastName'].strip()}")
                                elif "id" in user_info:
                                    changed_by = user_info["id"]
                                else:
                                    changed_by = "Unknown User"
                            else:
                                changed_by = "System"
                            break
                        # Look for specific SLO event types from audit logs
                        elif (log.event and 
                              log.event in ["slo_updated", "slo_created"] and
                              log.object_name == slo.name and 
                              log.project == slo.project):
                            # Parse user information from actor field
                            actor = log.actor
                            if actor and "user" in actor and actor["user"]:
                                user_info = actor["user"]
                                if "firstName" in user_info and "lastName" in user_info:
                                    changed_by = (f"{user_info['firstName'].strip()} "
                                               f"{user_info['lastName'].strip()}")
                                elif "id" in user_info:
                                    changed_by = user_info["id"]
                                else:
                                    changed_by = "Unknown User"
                            else:
                                changed_by = "System"
                            break
                    
                    recent_changes_data.append({
                        'Display Name': display_name,
                        'SLO Name': slo.name,
                        'Project': slo.project,
                        'Service': slo.service,
                        'Last Updated': slo.updated_at
                    })
                
                recent_df = pd.DataFrame(recent_changes_data)
                recent_df.to_excel(writer, sheet_name='Recent SLO Changes', index=False)
                self._auto_adjust_column_widths(writer, 'Recent SLO Changes', recent_df)
            else:
                pass
            
            # Top 10 Most Active Users sheet
            if summary.top_active_users:
                top_users_data = []
                for i, (user, count) in enumerate(summary.top_active_users, 1):
                    top_users_data.append({
                        'Rank': i,
                        'User': user,
                        'Change Count': count
                    })
                
                top_users_df = pd.DataFrame(top_users_data)
                # Clean up empty/None values to prevent empty columns
                top_users_df = top_users_df.replace(['', 'None'], pd.NA).dropna(axis=1, how='all')
                # Ensure we only have the expected columns
                expected_cols = ['Rank', 'User', 'Change Count']
                top_users_df = top_users_df[[col for col in expected_cols if col in top_users_df.columns]]
                top_users_df.to_excel(writer, sheet_name='Top 10 Most Active Users', index=False)
                self._auto_adjust_column_widths(writer, 'Top 10 Most Active Users', top_users_df)
            else:
                pass
            
            # Audit Trail Summary sheet
            if summary.top_active_users:
                # User activity
                user_activity_data = []
                total_changes = summary.last_7_days_changes
                for user, count in summary.top_active_users:
                    user_activity_data.append({
                        'User': user,
                        'Change Count': count,
                        'Percentage': f"{(count / total_changes) * 100:.1f}%" if total_changes > 0 else "0.0%"
                    })
                
                user_df = pd.DataFrame(user_activity_data)
                # Clean up empty/None values to prevent empty columns
                user_df = user_df.replace(['', 'None'], pd.NA).dropna(axis=1, how='all')
                # Ensure we only have the expected columns
                expected_cols = ['User', 'Change Count', 'Percentage']
                user_df = user_df[[col for col in expected_cols if col in user_df.columns]]
                user_df.to_excel(writer, sheet_name='User Activity', index=False)
                self._auto_adjust_column_widths(writer, 'User Activity', user_df)
                
                # Event types
                event_types = {}
                for log in self.audit_logs:
                    event = log.event
                    event_types[event] = event_types.get(event, 0) + 1
                
                if event_types:
                    event_data = []
                    for event, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
                        event_data.append({
                            'Event Type': event,
                            'Count': count,
                            'Percentage': f"{(count / len(self.audit_logs)) * 100:.1f}%"
                        })
                    
                    event_df = pd.DataFrame(event_data)
                    # Clean up empty/None values to prevent empty columns
                    event_df = event_df.replace(['', 'None'], pd.NA).dropna(axis=1, how='all')
                    # Ensure we only have the expected columns
                    expected_cols = ['Event Type', 'Count', 'Percentage']
                    event_df = event_df[[col for col in expected_cols if col in event_df.columns]]
                    event_df.to_excel(writer, sheet_name='Event Types', index=False)
                    self._auto_adjust_column_widths(writer, 'Event Types', event_df)
                else:
                    pass
            else:
                pass
            
        except Exception as e:
            print(f"Error during Excel export: {e}")
            print(f"Attempted to export to: {filename}")
            return
        
        print(f"Excel report exported to: {filename}")
        print("Note: Some sheets may be skipped if no relevant data is found (e.g., no unused alert policies, no audit trail data)")
    
    def _export_yaml(self, summary: AccountSummary):
        """Export organization SLOs to YAML format using sloctl"""
        print()
        print_header("YAML EXPORT")
        print_colored("Retrieving organization SLOs in YAML format...", colorama.Fore.CYAN)
        
        try:
            # Use sloctl to get all SLOs in YAML format
            result = subprocess.run(
                ["sloctl", "get", "slos", "-A", "-o", "yaml"],
                capture_output=True, text=True, check=True
            )
            
            if not result.stdout.strip():
                print_colored("No SLOs found or empty response from sloctl", colorama.Fore.YELLOW)
                return
            
            # Create timestamped filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nobl9_slos_{self.context_name}_{timestamp}.yaml"
            
            # Write YAML to file
            with open(filename, 'w') as f:
                f.write(result.stdout)
            
            print_colored(f"✓ YAML export completed successfully!", colorama.Fore.GREEN)
            print_colored(f"File: {filename}", colorama.Fore.WHITE)
            print_colored(f"Total SLOs exported: {len(self.slos)}", colorama.Fore.WHITE)
            
            # Show a preview of the YAML content
            print()
            print_colored("YAML Preview (first 500 characters):", colorama.Fore.CYAN)
            print_colored("-" * 50, colorama.Fore.CYAN)
            preview = result.stdout[:500].replace('\n', '\n  ')
            print_colored(f"  {preview}...", colorama.Fore.WHITE)
            
        except subprocess.CalledProcessError as e:
            print_colored(f"❌ Error running sloctl command: {e}", colorama.Fore.RED)
            print_colored("Make sure sloctl is properly configured and accessible", colorama.Fore.YELLOW)
        except Exception as e:
            print_colored(f"❌ Error during YAML export: {e}", colorama.Fore.RED)
    
    def _get_data_sources(self, source_type):
        """Get data sources (agents or directs) and map names to types"""
        try:
            result = subprocess.run(
                ["sloctl", "get", source_type, "-A", "-o", "json"],
                capture_output=True, text=True, check=True
            )
            
            # Check if stdout is empty
            if not result.stdout.strip():
                print(f"No {source_type} found or empty response from sloctl")
                return {}
            
            # Check for "No resources found" message
            if "No resources found" in result.stdout:
                print(f"No {source_type} found in any project")
                return {}
            
            data = json.loads(result.stdout)
            if isinstance(data, list):
                source_map = {}
                for source in data:
                    name = source.get("metadata", {}).get("name", "")
                    project = source.get("metadata", {}).get("project", "")
                    spec = source.get("spec", {})
                    
                    # Determine the actual type from the spec
                    if "prometheus" in spec:
                        source_type_name = "prometheus"
                    elif "cloudWatch" in spec:
                        source_type_name = "cloudwatch"
                    elif "splunk" in spec:
                        source_type_name = "splunk"
                    elif "dynatrace" in spec:
                        source_type_name = "dynatrace"
                    elif "datadog" in spec:
                        source_type_name = "datadog"
                    elif "newrelic" in spec:
                        source_type_name = "newrelic"
                    elif "lightstep" in spec:
                        source_type_name = "lightstep"
                    elif "gcm" in spec or "google" in spec:
                        source_type_name = "google_cloud"
                    elif "redshift" in spec:
                        source_type_name = "amazon_redshift"
                    elif "azureMonitor" in spec:
                        source_type_name = "azure_monitor"
                    elif "azurePrometheus" in spec:
                        source_type_name = "azure_prometheus"
                    elif "coralogix" in spec:
                        source_type_name = "coralogix"
                    elif "elasticsearch" in spec:
                        source_type_name = "elasticsearch"
                    elif "bigQuery" in spec:
                        source_type_name = "google_bigquery"
                    elif "loki" in spec:
                        source_type_name = "grafana_loki"
                    elif "graphite" in spec:
                        source_type_name = "graphite"
                    elif "influxdb" in spec:
                        source_type_name = "influxdb"
                    elif "instana" in spec:
                        source_type_name = "instana"
                    elif "logicMonitor" in spec:
                        source_type_name = "logicmonitor"
                    elif "openTSDB" in spec:
                        source_type_name = "opentsdb"
                    elif "pingdom" in spec:
                        source_type_name = "pingdom"
                    elif "serviceNow" in spec:
                        source_type_name = "servicenow"
                    elif "sumoLogic" in spec:
                        source_type_name = "sumo_logic"
                    elif "thousandEyes" in spec:
                        source_type_name = "thousandeyes"
                    elif "appDynamics" in spec:
                        source_type_name = "appdynamics"
                    else:
                        # Look for any other monitoring tool in spec
                        for key in spec.keys():
                            if key not in ["historicalDataRetrieval", "interval", "jitter", "timeout", "queryDelay", "releaseChannel", "logCollectionEnabled"]:
                                source_type_name = key
                                break
                        else:
                            source_type_name = "unknown"
                    
                    source_map[name] = source_type_name
                return source_map
            return {}
        except subprocess.CalledProcessError as e:
            print(f"Error getting {source_type}: {e}")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON for {source_type}: {e}")
            print(f"Raw output: {result.stdout[:200]}...")
            return {}

    def run_analysis(self, output_format: str = "console", audit_days: int = 7, context_name: str = None):
        """Run complete account analysis"""
        print("Starting Nobl9 Account Analysis...")
        
        # Setup authentication with specified context
        self._setup_authentication(context_name)
        
        print(f"Organization: {self.organization_id}")
        print()
        
        # Collect data
        self.collect_projects()
        self.collect_slos()
        self.collect_alert_policies()
        self.collect_services()
        self.collect_audit_logs(audit_days)
        
        # Get official usage summary for additional metrics
        usage_summary = self.get_usage_summary()
        self._usage_summary = usage_summary  # Store for exports
        
        # Analyze data
        summary = self.analyze_data()
        
        # Generate report
        self.generate_report(summary, output_format)
        
        return summary

    def get_usage_summary(self) -> Dict[str, Any]:
        """Get official resource usage summary from Nobl9 Reports API"""
        if not self.access_token:
            print("No access token available for API call")
            return {}
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Organization": self.organization_id
        }
        
        try:
            # Handle different base URL formats for custom instances
            if self.is_custom_instance:
                # For custom instances, check if base_url already includes /api
                if self.base_url.endswith('/api'):
                    url = f"{self.base_url}/reports/v1/usage-summary"
                else:
                    url = f"{self.base_url}/api/reports/v1/usage-summary"
            else:
                # Standard Nobl9 instance
                url = f"{self.base_url}/api/reports/v1/usage-summary"
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                # Check if response has content before trying to parse JSON
                if not response.text.strip():
                    print("⚠ Usage summary API returned empty response")
                    return {}
                
                try:
                    data = response.json()
                    print("Collected usage summary")
                    return data
                except ValueError as json_error:
                    # Check if response is HTML (likely a redirect to login page)
                    if response.headers.get('content-type', '').startswith('text/html'):
                        print("⚠ Usage summary API returned HTML instead of JSON - likely requires different permissions")
                        print("  This may indicate the Reports API is not accessible with current token")
                    else:
                        print(f"⚠ Failed to parse usage summary JSON: {json_error}")
                        print(f"Raw response: {response.text[:200]}...")
                    return {}
            elif response.status_code == 401:
                print("⚠ Authentication failed for usage summary API")
                return {}
            elif response.status_code == 429:
                print("⚠ Rate limit exceeded for usage summary API")
                return {}
            else:
                print(f"⚠ Failed to get usage summary: {response.status_code}")
                if response.text:
                    print(f"Response: {response.text[:200]}...")
                return {}
                
        except Exception as e:
            print(f"Error getting usage summary: {e}")
            return {}

    def _offer_export_options(self, summary: AccountSummary):
        """Offer export options at the end of the console report"""
        print()
        print_header("EXPORT OPTIONS")
        print_colored("Would you like to export this report?", colorama.Fore.CYAN)
        print()
        print_colored("Available formats:", colorama.Fore.WHITE)
        print_colored("  [1] CSV - Comma-separated values", colorama.Fore.WHITE)
        print_colored("  [2] JSON - JavaScript Object Notation", colorama.Fore.WHITE)
        print_colored("  [3] Excel - Multi-tab spreadsheet (.xlsx)", colorama.Fore.WHITE)
        print_colored("  [4] YAML - Organization SLOs in YAML format", colorama.Fore.WHITE)
        print_colored("  [5] Exit - No export", colorama.Fore.WHITE)
        print()
        
        try:
            choice = input("Select export format (1-5): ").strip()
            
            if choice == "1":
                self._export_csv(summary)
            elif choice == "2":
                self._export_json(summary)
            elif choice == "3":
                self._export_excel(summary)
            elif choice == "4":
                self._export_yaml(summary)
            elif choice == "5":
                print_colored("Exiting without export. Goodbye!", colorama.Fore.GREEN)
                return
            else:
                print_colored("Invalid choice. Exiting without export.", colorama.Fore.YELLOW)
                return
                
        except KeyboardInterrupt:
            print()
            print_colored("\nExport cancelled. Goodbye!", colorama.Fore.YELLOW)
            return
        except Exception as e:
            print_colored(f"Error during export: {e}", colorama.Fore.RED)
            return



def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Nobl9 Account Analyzer - Comprehensive account analysis and reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 account_analyzer.py                           # Console report
  python3 account_analyzer.py --context prod-us1        # Use specific context
  python3 account_analyzer.py --format csv              # CSV export
  python3 account_analyzer.py --format json             # JSON export
  python3 account_analyzer.py --format excel            # Excel export
  python3 account_analyzer.py --format yaml             # YAML export
  python3 account_analyzer.py --context staging-eu1 --format excel  # Context + format
  python3 account_analyzer.py --audit-days 30           # 30 days of audit data
        """
    )
    
    parser.add_argument(
        "--format", "-f",
        choices=["console", "csv", "json", "excel", "yaml"],
        default="console",
        help="Output format (default: console)"
    )
    
    parser.add_argument(
        "--context", "-c",
        type=str,
        help="Nobl9 context name to use (e.g., 'prod-us1')"
    )
    
    parser.add_argument(
        "--audit-days", "-a",
        type=int,
        default=7,
        help="Number of days of audit data to collect (default: 7)"
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = Nobl9AccountAnalyzer()
        analyzer.run_analysis(output_format=args.format, audit_days=args.audit_days, context_name=args.context)
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
