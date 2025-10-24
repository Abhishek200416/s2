#!/usr/bin/env python3
"""
Focused test for Auto-Decide functionality only
"""

import requests
import json
import sys
import os
from datetime import datetime
import time

# Get backend URL from frontend .env file
try:
    with open('/app/frontend/.env', 'r') as f:
        for line in f:
            if line.startswith('REACT_APP_BACKEND_URL='):
                base_url = line.split('=', 1)[1].strip()
                # Add /api suffix if not present
                if not base_url.endswith('/api'):
                    BACKEND_URL = f"{base_url}/api"
                else:
                    BACKEND_URL = base_url
                break
        else:
            BACKEND_URL = "http://localhost:8001/api"
except:
    BACKEND_URL = "http://localhost:8001/api"

class AutoDecideTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.session = requests.Session()
        self.auth_token = None
        
    def log_result(self, test_name, success, message, details=None):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name} - {message}")
        if details and not success:
            print(f"   Details: {details}")
    
    def make_request(self, method, endpoint, **kwargs):
        """Make HTTP request with proper error handling"""
        url = f"{self.base_url}{endpoint}"
        try:
            if self.auth_token:
                headers = kwargs.get('headers', {})
                headers['Authorization'] = f'Bearer {self.auth_token}'
                kwargs['headers'] = headers
            
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request exception: {e}")
            return None
    
    def login(self):
        """Login to get auth token"""
        login_data = {
            "email": "admin@alertwhisperer.com",
            "password": "admin123"
        }
        
        response = self.make_request('POST', '/auth/login', json=login_data)
        if response and response.status_code == 200:
            data = response.json()
            self.auth_token = data.get('access_token')
            print(f"✅ Logged in as {data.get('user', {}).get('name', 'Unknown')}")
            return True
        else:
            print(f"❌ Login failed: {response.status_code if response else 'No response'}")
            return False
    
    def test_auto_decide_config(self):
        """Test auto-decide configuration endpoints"""
        print("\n=== Testing Auto-Decide Configuration ===")
        
        # Reset to default config first
        default_config = {
            "company_id": "company-demo",
            "enabled": True,
            "interval_seconds": 1
        }
        
        response = self.make_request('PUT', '/auto-decide/config', json=default_config)
        if response and response.status_code == 200:
            print("✅ Reset to default config")
        
        # Test 1: GET default config
        response = self.make_request('GET', '/auto-decide/config?company_id=company-demo')
        if response and response.status_code == 200:
            config = response.json()
            enabled = config.get('enabled')
            interval_seconds = config.get('interval_seconds')
            company_id = config.get('company_id')
            
            if enabled is True and interval_seconds == 1 and company_id == "company-demo":
                self.log_result("Get Default Config", True, f"Default config verified: enabled={enabled}, interval={interval_seconds}s")
            else:
                self.log_result("Get Default Config", False, f"Config values incorrect: enabled={enabled}, interval={interval_seconds}, company={company_id}")
        else:
            self.log_result("Get Default Config", False, f"Failed to get config: {response.status_code if response else 'No response'}")
        
        # Test 2: Update config
        update_config = {
            "company_id": "company-demo",
            "enabled": False,
            "interval_seconds": 5
        }
        
        response = self.make_request('PUT', '/auto-decide/config', json=update_config)
        if response and response.status_code == 200:
            updated_config = response.json()
            if updated_config.get('enabled') == False and updated_config.get('interval_seconds') == 5:
                self.log_result("Update Config", True, f"Config updated: enabled={updated_config.get('enabled')}, interval={updated_config.get('interval_seconds')}s")
            else:
                self.log_result("Update Config", False, "Config update didn't apply correctly")
        else:
            self.log_result("Update Config", False, f"Failed to update config: {response.status_code if response else 'No response'}")
        
        # Test 3: Verify persistence
        response = self.make_request('GET', '/auto-decide/config?company_id=company-demo')
        if response and response.status_code == 200:
            config = response.json()
            if config.get('enabled') == False and config.get('interval_seconds') == 5:
                self.log_result("Verify Persistence", True, f"Config persisted: enabled={config.get('enabled')}, interval={config.get('interval_seconds')}s")
            else:
                self.log_result("Verify Persistence", False, f"Config not persisted: enabled={config.get('enabled')}, interval={config.get('interval_seconds')}")
        else:
            self.log_result("Verify Persistence", False, f"Failed to verify persistence: {response.status_code if response else 'No response'}")
    
    def test_auto_decide_workflow(self):
        """Test the complete auto-decide workflow"""
        print("\n=== Testing Auto-Decide Workflow ===")
        
        # Step 1: Use existing comp-acme company instead of demo
        company_response = self.make_request('GET', '/companies/comp-acme')
        if company_response and company_response.status_code == 200:
            company = company_response.json()
            api_key = company.get('api_key')
            company_id = company.get('id')
            
            if api_key:
                self.log_result("Company Setup", True, f"Company ready: {company_id}, API key: {api_key[:20]}...")
                
                # Step 2: Create test alerts
                alerts_created = []
                for i in range(3):
                    webhook_payload = {
                        "asset_name": "srv-auto-decide-01",
                        "signature": "auto_decide_test_alert",
                        "severity": "high",
                        "message": f"Auto-decide test alert {i+1}",
                        "tool_source": "AutoDecideTest"
                    }
                    
                    try:
                        webhook_url = f'/webhooks/alerts?api_key={api_key}'
                        response = self.make_request('POST', webhook_url, json=webhook_payload, timeout=10)
                        if response and response.status_code == 200:
                            webhook_result = response.json()
                            alert_id = webhook_result.get('alert_id')
                            alerts_created.append(alert_id)
                            print(f"  Created alert {i+1}: {alert_id}")
                        else:
                            print(f"  Failed to create alert {i+1}: {response.status_code if response else 'No response'}")
                            if response:
                                print(f"    Response: {response.text}")
                    except Exception as e:
                        print(f"  Exception creating alert {i+1}: {e}")
                
                if len(alerts_created) >= 3:
                    self.log_result("Create Test Alerts", True, f"Created {len(alerts_created)} test alerts")
                    
                    # Wait for alerts to be processed
                    time.sleep(2)
                    
                    # Step 3: Run correlation
                    response = self.make_request('POST', f'/incidents/correlate?company_id={company_id}')
                    if response and response.status_code == 200:
                        correlation_result = response.json()
                        incidents_created = correlation_result.get('incidents_created', 0)
                        self.log_result("Run Correlation", True, f"Correlation completed: {incidents_created} incidents created")
                        
                        # Step 4: Run auto-decide
                        response = self.make_request('POST', f'/auto-decide/run?company_id={company_id}')
                        if response and response.status_code == 200:
                            auto_decide_result = response.json()
                            
                            # Check response structure
                            required_fields = ['incidents_processed', 'incidents_assigned', 'incidents_executed', 'timestamp']
                            missing_fields = [field for field in required_fields if field not in auto_decide_result]
                            
                            if not missing_fields:
                                processed = auto_decide_result.get('incidents_processed', 0)
                                assigned = auto_decide_result.get('incidents_assigned', 0)
                                executed = auto_decide_result.get('incidents_executed', 0)
                                
                                self.log_result("Auto-Decide Run", True, f"Auto-decide completed: {processed} processed, {assigned} assigned, {executed} executed")
                                
                                # Step 5: Verify incidents have decisions
                                response = self.make_request('GET', f'/incidents?company_id={company_id}')
                                if response and response.status_code == 200:
                                    incidents = response.json()
                                    
                                    # Find incidents with decisions
                                    incidents_with_decisions = [inc for inc in incidents if inc.get('decision')]
                                    
                                    if incidents_with_decisions:
                                        sample_incident = incidents_with_decisions[0]
                                        decision = sample_incident.get('decision', {})
                                        status = sample_incident.get('status')
                                        assigned_to = sample_incident.get('assigned_to')
                                        
                                        self.log_result("Verify Integration", True, f"Found incident with decision: action={decision.get('action')}, status={status}, assigned={bool(assigned_to)}")
                                    else:
                                        self.log_result("Verify Integration", False, "No incidents found with decisions after auto-decide")
                                else:
                                    self.log_result("Verify Integration", False, f"Failed to get incidents: {response.status_code if response else 'No response'}")
                            else:
                                self.log_result("Auto-Decide Run", False, f"Response missing fields: {missing_fields}")
                        else:
                            self.log_result("Auto-Decide Run", False, f"Failed to run auto-decide: {response.status_code if response else 'No response'}")
                            if response:
                                print(f"    Response: {response.text}")
                    else:
                        self.log_result("Run Correlation", False, f"Failed to run correlation: {response.status_code if response else 'No response'}")
                        if response:
                            print(f"    Response: {response.text}")
                else:
                    self.log_result("Create Test Alerts", False, f"Failed to create sufficient alerts: {len(alerts_created)}/3")
            else:
                self.log_result("Company Setup", False, "Company found but no API key")
        else:
            self.log_result("Company Setup", False, f"Failed to get company: {company_response.status_code if company_response else 'No response'}")
            if company_response:
                print(f"    Response: {company_response.text}")
    
    def run_tests(self):
        """Run all auto-decide tests"""
        print("🚀 Auto-Decide Functionality Test Suite")
        print(f"Backend URL: {self.base_url}")
        print("=" * 60)
        
        if not self.login():
            return
        
        self.test_auto_decide_config()
        self.test_auto_decide_workflow()

if __name__ == "__main__":
    tester = AutoDecideTester()
    tester.run_tests()