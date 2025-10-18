#!/usr/bin/env python3
"""
Demo Mode and Auto-Correlation Endpoints Test Suite
Tests the newly fixed endpoints as requested in the review:
1. Demo Mode endpoints (company, generate-data, script)
2. Auto-Correlation configuration endpoints
3. Technician Categories and Asset Types endpoints
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
                BACKEND_URL = line.split('=', 1)[1].strip()
                break
        else:
            BACKEND_URL = "http://localhost:8001/api"
except:
    BACKEND_URL = "http://localhost:8001/api"

class DemoAutoCorrelationTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.session = requests.Session()
        self.auth_token = None
        self.test_results = []
        self.demo_company_id = None
        
    def log_result(self, test_name, success, message, details=None):
        """Log test result"""
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
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
    
    def authenticate(self):
        """Authenticate with admin credentials"""
        print("\n=== Authentication ===")
        
        login_data = {
            "email": "admin@alertwhisperer.com",
            "password": "admin123"
        }
        
        response = self.make_request('POST', '/auth/login', json=login_data)
        if response is None:
            self.log_result("Authentication", False, "Request failed - backend not accessible")
            return False
            
        if response.status_code == 200:
            data = response.json()
            self.auth_token = data.get('access_token')
            user_name = data.get('user', {}).get('name', 'Unknown')
            self.log_result("Authentication", True, f"Successfully logged in as {user_name}")
            return True
        else:
            self.log_result("Authentication", False, f"Login failed with status {response.status_code}", response.text)
            return False
    
    def test_demo_company_endpoint(self):
        """Test 1: GET /api/demo/company - Should create/return demo company with 3 assets"""
        print("\n=== Testing Demo Company Endpoint ===")
        
        response = self.make_request('GET', '/demo/company')
        if response and response.status_code == 200:
            demo_company = response.json()
            
            # Check required fields
            company_id = demo_company.get('id')
            company_name = demo_company.get('name')
            assets = demo_company.get('assets', [])
            
            if company_id and company_name and len(assets) == 3:
                self.demo_company_id = company_id
                asset_names = [asset.get('name') for asset in assets]
                self.log_result("Demo Company Creation", True, 
                              f"Demo company created: {company_name} (ID: {company_id}) with 3 assets: {asset_names}")
                
                # Verify each asset has required fields
                all_assets_valid = True
                for asset in assets:
                    if not all(field in asset for field in ['id', 'name', 'type']):
                        all_assets_valid = False
                        break
                
                if all_assets_valid:
                    self.log_result("Demo Company Assets", True, "All 3 assets have required fields (id, name, type)")
                else:
                    self.log_result("Demo Company Assets", False, "Some assets missing required fields")
                    
            else:
                missing = []
                if not company_id: missing.append("company_id")
                if not company_name: missing.append("company_name")
                if len(assets) != 3: missing.append(f"3_assets (got {len(assets)})")
                self.log_result("Demo Company Creation", False, f"Demo company missing: {missing}")
        else:
            self.log_result("Demo Company Creation", False, 
                          f"Failed to get demo company: {response.status_code if response else 'No response'}")
    
    def test_demo_generate_data_endpoint(self):
        """Test 2: POST /api/demo/generate-data - Generate 100 demo alerts"""
        print("\n=== Testing Demo Generate Data Endpoint ===")
        
        if not self.demo_company_id:
            self.log_result("Demo Generate Data Setup", False, "No demo company ID available")
            return
        
        # Test generating 100 alerts
        generate_data = {
            "count": 100,
            "company_id": self.demo_company_id
        }
        
        response = self.make_request('POST', '/demo/generate-data', json=generate_data)
        if response and response.status_code == 200:
            result = response.json()
            
            # Check response structure
            alerts_created = result.get('count')  # Backend returns 'count' not 'alerts_created'
            company_id = result.get('company_id')
            message = result.get('message', '')
            
            if alerts_created == 100 and company_id == self.demo_company_id:
                self.log_result("Demo Generate 100 Alerts", True, 
                              f"Successfully generated {alerts_created} alerts for company {company_id}")
                
                # Verify alerts were actually created by checking alerts endpoint
                time.sleep(2)  # Wait for alerts to be processed
                verify_response = self.make_request('GET', f'/alerts?company_id={self.demo_company_id}')
                if verify_response and verify_response.status_code == 200:
                    alerts = verify_response.json()
                    if len(alerts) >= 100:
                        self.log_result("Demo Alerts Verification", True, 
                                      f"Verified {len(alerts)} alerts created in database")
                    else:
                        self.log_result("Demo Alerts Verification", False, 
                                      f"Only {len(alerts)} alerts found in database, expected 100+")
                else:
                    self.log_result("Demo Alerts Verification", False, 
                                  f"Failed to verify alerts: {verify_response.status_code if verify_response else 'No response'}")
            else:
                issues = []
                if alerts_created != 100: issues.append(f"alerts_created={alerts_created} (expected 100)")
                if company_id != self.demo_company_id: issues.append(f"company_id mismatch")
                self.log_result("Demo Generate 100 Alerts", False, f"Generation issues: {issues}")
        else:
            self.log_result("Demo Generate 100 Alerts", False, 
                          f"Failed to generate alerts: {response.status_code if response else 'No response'}")
    
    def test_demo_script_endpoint(self):
        """Test 3: GET /api/demo/script - Get Python testing script"""
        print("\n=== Testing Demo Script Endpoint ===")
        
        # Use demo company ID as query parameter
        company_id = self.demo_company_id or "company-demo"
        response = self.make_request('GET', f'/demo/script?company_id={company_id}')
        if response and response.status_code == 200:
            script_data = response.json()
            
            # Check response structure
            script_content = script_data.get('script')
            filename = script_data.get('filename')
            instructions = script_data.get('instructions')  # Backend returns 'instructions' not 'description'
            
            if script_content and filename and instructions:
                # Verify script contains key elements
                script_checks = [
                    'import requests' in script_content,
                    'hmac' in script_content.lower(),
                    'webhook' in script_content.lower(),
                    'api_key' in script_content.lower()
                ]
                
                if all(script_checks):
                    script_lines = len(script_content.split('\n'))
                    self.log_result("Demo Script Generation", True, 
                                  f"Python script generated: {filename} ({script_lines} lines) with HMAC support")
                else:
                    missing_elements = []
                    if 'import requests' not in script_content: missing_elements.append("requests import")
                    if 'hmac' not in script_content.lower(): missing_elements.append("HMAC support")
                    if 'webhook' not in script_content.lower(): missing_elements.append("webhook functionality")
                    if 'api_key' not in script_content.lower(): missing_elements.append("API key usage")
                    
                    self.log_result("Demo Script Generation", False, f"Script missing: {missing_elements}")
            else:
                missing = []
                if not script_content: missing.append("script_content")
                if not filename: missing.append("filename")
                if not instructions: missing.append("instructions")
                self.log_result("Demo Script Generation", False, f"Script response missing: {missing}")
        else:
            self.log_result("Demo Script Generation", False, 
                          f"Failed to get demo script: {response.status_code if response else 'No response'}")
    
    def test_auto_correlation_config_get(self):
        """Test 4: GET /api/auto-correlation/config?company_id=company-demo"""
        print("\n=== Testing Auto-Correlation Config GET ===")
        
        # Use demo company ID if available, otherwise use a default
        company_id = self.demo_company_id or "company-demo"
        
        response = self.make_request('GET', f'/auto-correlation/config?company_id={company_id}')
        if response and response.status_code == 200:
            config = response.json()
            
            # Check required fields
            required_fields = ['enabled', 'interval_minutes', 'last_run', 'company_id']
            missing_fields = [field for field in required_fields if field not in config]
            
            if not missing_fields:
                enabled = config.get('enabled')
                interval = config.get('interval_minutes')
                last_run = config.get('last_run')
                
                self.log_result("Auto-Correlation Config GET", True, 
                              f"Config retrieved: enabled={enabled}, interval={interval}min, last_run={last_run}")
            else:
                self.log_result("Auto-Correlation Config GET", False, f"Config missing fields: {missing_fields}")
        else:
            self.log_result("Auto-Correlation Config GET", False, 
                          f"Failed to get auto-correlation config: {response.status_code if response else 'No response'}")
    
    def test_auto_correlation_config_update(self):
        """Test 5: PUT /api/auto-correlation/config - Update interval to 5 minutes"""
        print("\n=== Testing Auto-Correlation Config UPDATE ===")
        
        # Use demo company ID if available, otherwise use a default
        company_id = self.demo_company_id or "company-demo"
        
        update_data = {
            "company_id": company_id,
            "interval_minutes": 5,
            "enabled": True
        }
        
        response = self.make_request('PUT', '/auto-correlation/config', json=update_data)
        if response and response.status_code == 200:
            updated_config = response.json()
            
            # Verify the update was applied
            new_interval = updated_config.get('interval_minutes')
            enabled = updated_config.get('enabled')
            
            if new_interval == 5 and enabled == True:
                self.log_result("Auto-Correlation Config UPDATE", True, 
                              f"Config updated successfully: interval={new_interval}min, enabled={enabled}")
            else:
                self.log_result("Auto-Correlation Config UPDATE", False, 
                              f"Config update failed: interval={new_interval}, enabled={enabled}")
        else:
            self.log_result("Auto-Correlation Config UPDATE", False, 
                          f"Failed to update auto-correlation config: {response.status_code if response else 'No response'}")
    
    def test_auto_correlation_run(self):
        """Test 6: POST /api/auto-correlation/run - Manually trigger correlation"""
        print("\n=== Testing Auto-Correlation Manual Run ===")
        
        # Use demo company ID if available, otherwise use a default
        company_id = self.demo_company_id or "company-demo"
        
        # Use company_id as query parameter
        response = self.make_request('POST', f'/auto-correlation/run?company_id={company_id}')
        if response and response.status_code == 200:
            run_result = response.json()
            
            # Check response structure for correlation statistics
            required_fields = ['alerts_before', 'alerts_after', 'incidents_created', 'noise_removed', 'duplicates_found']
            missing_fields = [field for field in required_fields if field not in run_result]
            
            if not missing_fields:
                alerts_before = run_result.get('alerts_before')
                alerts_after = run_result.get('alerts_after')
                incidents_created = run_result.get('incidents_created')
                noise_removed = run_result.get('noise_removed')
                duplicates_found = run_result.get('duplicates_found')
                
                self.log_result("Auto-Correlation Manual Run", True, 
                              f"Correlation completed: {alerts_before}→{alerts_after} alerts, {incidents_created} incidents, {noise_removed}% noise removed, {duplicates_found} duplicates")
            else:
                self.log_result("Auto-Correlation Manual Run", False, f"Run result missing fields: {missing_fields}")
        else:
            self.log_result("Auto-Correlation Manual Run", False, 
                          f"Failed to run auto-correlation: {response.status_code if response else 'No response'}")
    
    def test_technician_categories(self):
        """Test 7: GET /api/technician-categories - Verify 8 MSP categories"""
        print("\n=== Testing Technician Categories ===")
        
        response = self.make_request('GET', '/technician-categories')
        if response and response.status_code == 200:
            categories_data = response.json()
            
            categories = categories_data.get('categories', [])
            description = categories_data.get('description', '')
            
            if len(categories) == 8:
                expected_categories = ["Network", "Database", "Security", "Server", "Application", "Storage", "Cloud", "Custom"]
                missing_categories = [cat for cat in expected_categories if cat not in categories]
                
                if not missing_categories:
                    self.log_result("Technician Categories", True, 
                                  f"All 8 MSP categories found: {categories}")
                else:
                    self.log_result("Technician Categories", False, f"Missing categories: {missing_categories}")
            else:
                self.log_result("Technician Categories", False, 
                              f"Expected 8 categories, got {len(categories)}: {categories}")
        else:
            self.log_result("Technician Categories", False, 
                          f"Failed to get technician categories: {response.status_code if response else 'No response'}")
    
    def test_asset_types(self):
        """Test 8: GET /api/asset-types - Verify 10 MSP asset types"""
        print("\n=== Testing Asset Types ===")
        
        response = self.make_request('GET', '/asset-types')
        if response and response.status_code == 200:
            asset_types_data = response.json()
            
            asset_types = asset_types_data.get('asset_types', [])
            description = asset_types_data.get('description', '')
            
            if len(asset_types) == 10:
                expected_types = ["Server", "Network Device", "Database", "Application", "Storage", 
                                "Cloud Resource", "Virtual Machine", "Container", "Load Balancer", "Firewall"]
                missing_types = [asset_type for asset_type in expected_types if asset_type not in asset_types]
                
                if not missing_types:
                    self.log_result("Asset Types", True, 
                                  f"All 10 MSP asset types found: {asset_types}")
                else:
                    self.log_result("Asset Types", False, f"Missing asset types: {missing_types}")
            else:
                self.log_result("Asset Types", False, 
                              f"Expected 10 asset types, got {len(asset_types)}: {asset_types}")
        else:
            self.log_result("Asset Types", False, 
                          f"Failed to get asset types: {response.status_code if response else 'No response'}")
    
    def run_all_tests(self):
        """Run all demo mode and auto-correlation tests"""
        print("🚀 Starting Demo Mode and Auto-Correlation Endpoint Tests")
        print(f"Backend URL: {self.base_url}")
        
        # Authenticate first
        if not self.authenticate():
            print("❌ Authentication failed, cannot proceed with tests")
            return
        
        # Run all tests in sequence
        self.test_demo_company_endpoint()
        self.test_demo_generate_data_endpoint()
        self.test_demo_script_endpoint()
        self.test_auto_correlation_config_get()
        self.test_auto_correlation_config_update()
        self.test_auto_correlation_run()
        self.test_technician_categories()
        self.test_asset_types()
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("📊 DEMO MODE & AUTO-CORRELATION TEST SUMMARY")
        print("="*60)
        
        passed = sum(1 for result in self.test_results if result['success'])
        total = len(self.test_results)
        success_rate = (passed / total * 100) if total > 0 else 0
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if total - passed > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  • {result['test']}: {result['message']}")
        
        print("\n✅ PASSED TESTS:")
        for result in self.test_results:
            if result['success']:
                print(f"  • {result['test']}: {result['message']}")

if __name__ == "__main__":
    tester = DemoAutoCorrelationTester()
    tester.run_all_tests()