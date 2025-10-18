#!/usr/bin/env python3
"""
Demo Mode and Auto-Correlation Features Test Suite
Tests the newly implemented features as requested in the review:

1. Demo Mode Endpoints:
   - GET /api/demo/company - Create or return demo company with assets
   - POST /api/demo/generate-data - Generate 100 test alerts for demo company
   - GET /api/demo/script - Get Python testing script

2. Auto-Correlation Endpoints:
   - GET /api/auto-correlation/config - Get auto-correlation config
   - PUT /api/auto-correlation/config - Update interval to 5 minutes
   - POST /api/auto-correlation/run - Run correlation and get statistics

3. Technician & Asset Types:
   - GET /api/technician-categories - MSP categories
   - GET /api/asset-types - Asset types
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
        """Authenticate with the system"""
        print("\n=== Authenticating ===")
        
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
            self.log_result("Authentication", True, f"Successfully logged in as {data.get('user', {}).get('name', 'Unknown')}")
            return True
        else:
            self.log_result("Authentication", False, f"Login failed with status {response.status_code}", response.text)
            return False
    
    def test_demo_company_endpoint(self):
        """Test 1: GET /api/demo/company - Should create or return demo company with assets"""
        print("\n=== Testing Demo Company Endpoint ===")
        
        response = self.make_request('GET', '/demo/company')
        if response and response.status_code == 200:
            demo_company = response.json()
            
            # Check required fields
            required_fields = ['id', 'name', 'assets']
            missing_fields = [field for field in required_fields if field not in demo_company]
            
            if not missing_fields:
                company_id = demo_company.get('id')
                company_name = demo_company.get('name')
                assets = demo_company.get('assets', [])
                
                # Store demo company ID for later tests
                self.demo_company_id = company_id
                
                # Check if demo company has 3 assets as expected
                if len(assets) >= 3:
                    asset_names = [asset.get('name', 'Unknown') for asset in assets]
                    self.log_result("Demo Company Creation", True, 
                                  f"Demo company '{company_name}' created/retrieved with {len(assets)} assets: {', '.join(asset_names[:3])}")
                else:
                    self.log_result("Demo Company Creation", False, 
                                  f"Demo company has {len(assets)} assets, expected at least 3")
            else:
                self.log_result("Demo Company Creation", False, f"Missing required fields: {missing_fields}")
        else:
            self.log_result("Demo Company Creation", False, 
                          f"Failed to get demo company: {response.status_code if response else 'No response'}")
    
    def test_demo_generate_data_endpoint(self):
        """Test 2: POST /api/demo/generate-data - Generate 100 test alerts for demo company"""
        print("\n=== Testing Demo Generate Data Endpoint ===")
        
        if not self.demo_company_id:
            self.log_result("Demo Generate Data Setup", False, "No demo company ID available")
            return
        
        # Test generating 100 alerts
        generate_data = {
            "company_id": self.demo_company_id,
            "count": 100
        }
        
        response = self.make_request('POST', '/demo/generate-data', json=generate_data)
        if response and response.status_code == 200:
            generation_result = response.json()
            
            # Check required response fields
            required_fields = ['alerts_created', 'company_id', 'message']
            missing_fields = [field for field in required_fields if field not in generation_result]
            
            if not missing_fields:
                alerts_created = generation_result.get('alerts_created', 0)
                message = generation_result.get('message', '')
                
                if alerts_created == 100:
                    self.log_result("Demo Generate 100 Alerts", True, 
                                  f"Successfully generated {alerts_created} alerts for demo company")
                else:
                    self.log_result("Demo Generate 100 Alerts", False, 
                                  f"Expected 100 alerts, got {alerts_created}")
                
                # Verify alerts were actually created by checking alerts endpoint
                response = self.make_request('GET', f'/alerts?company_id={self.demo_company_id}')
                if response and response.status_code == 200:
                    alerts = response.json()
                    if len(alerts) >= 100:
                        # Check alert variety (severities and categories)
                        severities = set(alert.get('severity') for alert in alerts)
                        tool_sources = set(alert.get('tool_source') for alert in alerts)
                        
                        self.log_result("Demo Alert Variety", True, 
                                      f"Generated alerts have {len(severities)} severities ({', '.join(severities)}) and {len(tool_sources)} tool sources")
                    else:
                        self.log_result("Demo Alert Verification", False, 
                                      f"Only {len(alerts)} alerts found in database, expected at least 100")
                else:
                    self.log_result("Demo Alert Verification", False, 
                                  f"Failed to verify alerts: {response.status_code if response else 'No response'}")
            else:
                self.log_result("Demo Generate 100 Alerts", False, f"Missing required fields: {missing_fields}")
        else:
            self.log_result("Demo Generate 100 Alerts", False, 
                          f"Failed to generate demo data: {response.status_code if response else 'No response'}")
    
    def test_demo_script_endpoint(self):
        """Test 3: GET /api/demo/script - Get Python testing script"""
        print("\n=== Testing Demo Script Endpoint ===")
        
        if not self.demo_company_id:
            self.log_result("Demo Script Setup", False, "No demo company ID available")
            return
        
        response = self.make_request('GET', f'/demo/script?company_id={self.demo_company_id}')
        if response and response.status_code == 200:
            script_result = response.json()
            
            # Check required fields
            required_fields = ['script', 'filename', 'description']
            missing_fields = [field for field in required_fields if field not in script_result]
            
            if not missing_fields:
                script_content = script_result.get('script', '')
                filename = script_result.get('filename', '')
                description = script_result.get('description', '')
                
                # Verify script contains essential elements
                script_checks = {
                    'import requests': 'import requests' in script_content,
                    'webhook endpoint': '/webhooks/alerts' in script_content,
                    'HMAC signature': 'hmac' in script_content.lower(),
                    'API key': 'api_key' in script_content,
                    'company_id': self.demo_company_id in script_content
                }
                
                passed_checks = sum(script_checks.values())
                total_checks = len(script_checks)
                
                if passed_checks >= 4:  # Allow some flexibility
                    self.log_result("Demo Python Script", True, 
                                  f"Generated Python script ({len(script_content)} chars) with {passed_checks}/{total_checks} required elements")
                else:
                    failed_checks = [check for check, passed in script_checks.items() if not passed]
                    self.log_result("Demo Python Script", False, 
                                  f"Script missing elements: {', '.join(failed_checks)}")
            else:
                self.log_result("Demo Python Script", False, f"Missing required fields: {missing_fields}")
        else:
            self.log_result("Demo Python Script", False, 
                          f"Failed to get demo script: {response.status_code if response else 'No response'}")
    
    def test_auto_correlation_config_get(self):
        """Test 4: GET /api/auto-correlation/config - Get auto-correlation config"""
        print("\n=== Testing Auto-Correlation Config GET ===")
        
        if not self.demo_company_id:
            self.log_result("Auto-Correlation Config Setup", False, "No demo company ID available")
            return
        
        response = self.make_request('GET', f'/auto-correlation/config?company_id={self.demo_company_id}')
        if response and response.status_code == 200:
            config = response.json()
            
            # Check required fields
            required_fields = ['enabled', 'interval_minutes', 'last_run']
            missing_fields = [field for field in required_fields if field not in config]
            
            if not missing_fields:
                enabled = config.get('enabled')
                interval_minutes = config.get('interval_minutes')
                last_run = config.get('last_run')
                
                self.log_result("Auto-Correlation Config GET", True, 
                              f"Retrieved config: enabled={enabled}, interval={interval_minutes}min, last_run={last_run}")
            else:
                self.log_result("Auto-Correlation Config GET", False, f"Missing required fields: {missing_fields}")
        else:
            self.log_result("Auto-Correlation Config GET", False, 
                          f"Failed to get auto-correlation config: {response.status_code if response else 'No response'}")
    
    def test_auto_correlation_config_update(self):
        """Test 5: PUT /api/auto-correlation/config - Update interval to 5 minutes"""
        print("\n=== Testing Auto-Correlation Config UPDATE ===")
        
        if not self.demo_company_id:
            self.log_result("Auto-Correlation Config Update Setup", False, "No demo company ID available")
            return
        
        # Update config to 5 minutes interval
        update_data = {
            "company_id": self.demo_company_id,
            "enabled": True,
            "interval_minutes": 5
        }
        
        response = self.make_request('PUT', '/auto-correlation/config', json=update_data)
        if response and response.status_code == 200:
            updated_config = response.json()
            
            # Verify the update
            enabled = updated_config.get('enabled')
            interval_minutes = updated_config.get('interval_minutes')
            
            if enabled == True and interval_minutes == 5:
                self.log_result("Auto-Correlation Config UPDATE", True, 
                              f"Config updated successfully: enabled={enabled}, interval={interval_minutes}min")
                
                # Verify persistence by getting config again
                verify_response = self.make_request('GET', f'/auto-correlation/config?company_id={self.demo_company_id}')
                if verify_response and verify_response.status_code == 200:
                    verify_config = verify_response.json()
                    if verify_config.get('interval_minutes') == 5:
                        self.log_result("Auto-Correlation Config Persistence", True, 
                                      "Config update persisted correctly")
                    else:
                        self.log_result("Auto-Correlation Config Persistence", False, 
                                      f"Config not persisted, got interval: {verify_config.get('interval_minutes')}")
                else:
                    self.log_result("Auto-Correlation Config Persistence", False, 
                                  "Failed to verify config persistence")
            else:
                self.log_result("Auto-Correlation Config UPDATE", False, 
                              f"Config not updated correctly: enabled={enabled}, interval={interval_minutes}")
        else:
            self.log_result("Auto-Correlation Config UPDATE", False, 
                          f"Failed to update auto-correlation config: {response.status_code if response else 'No response'}")
    
    def test_auto_correlation_run(self):
        """Test 6: POST /api/auto-correlation/run - Run correlation and get statistics"""
        print("\n=== Testing Auto-Correlation RUN ===")
        
        if not self.demo_company_id:
            self.log_result("Auto-Correlation Run Setup", False, "No demo company ID available")
            return
        
        response = self.make_request('POST', f'/auto-correlation/run?company_id={self.demo_company_id}')
        if response and response.status_code == 200:
            correlation_result = response.json()
            
            # Check required statistics fields
            required_fields = ['alerts_before', 'alerts_after', 'incidents_created', 'noise_removed', 'duplicates_found']
            missing_fields = [field for field in required_fields if field not in correlation_result]
            
            if not missing_fields:
                alerts_before = correlation_result.get('alerts_before', 0)
                alerts_after = correlation_result.get('alerts_after', 0)
                incidents_created = correlation_result.get('incidents_created', 0)
                noise_removed = correlation_result.get('noise_removed', 0)
                duplicates_found = correlation_result.get('duplicates_found', 0)
                
                # Calculate noise reduction percentage
                noise_reduction_pct = 0
                if alerts_before > 0:
                    noise_reduction_pct = (noise_removed / alerts_before) * 100
                
                self.log_result("Auto-Correlation RUN", True, 
                              f"Correlation completed: {alerts_before}→{alerts_after} alerts, {incidents_created} incidents, {noise_removed} noise removed ({noise_reduction_pct:.1f}%), {duplicates_found} duplicates")
                
                # Verify that correlation actually processed alerts
                if alerts_before > 0:
                    self.log_result("Auto-Correlation Processing", True, 
                                  f"Correlation processed {alerts_before} alerts successfully")
                else:
                    self.log_result("Auto-Correlation Processing", False, 
                                  "No alerts were processed by correlation (may need to generate demo data first)")
                
                # Check if duplicates structure is provided
                duplicates_data = correlation_result.get('duplicates', {})
                if isinstance(duplicates_data, dict) and 'count' in duplicates_data:
                    duplicate_groups = duplicates_data.get('groups', [])
                    self.log_result("Auto-Correlation Duplicates Detail", True, 
                                  f"Duplicates detail provided: {len(duplicate_groups)} groups")
                else:
                    self.log_result("Auto-Correlation Duplicates Detail", False, 
                                  "Duplicates detail structure missing or incomplete")
            else:
                self.log_result("Auto-Correlation RUN", False, f"Missing required statistics: {missing_fields}")
        else:
            self.log_result("Auto-Correlation RUN", False, 
                          f"Failed to run auto-correlation: {response.status_code if response else 'No response'}")
    
    def test_technician_categories(self):
        """Test 7: GET /api/technician-categories - Should return list of MSP categories"""
        print("\n=== Testing Technician Categories ===")
        
        response = self.make_request('GET', '/technician-categories')
        if response and response.status_code == 200:
            categories_result = response.json()
            
            # Check response structure
            if 'categories' in categories_result:
                categories = categories_result.get('categories', [])
                description = categories_result.get('description', '')
                
                # Expected MSP categories
                expected_categories = ['Network', 'Database', 'Security', 'Server', 'Application', 'Storage', 'Cloud', 'Custom']
                
                # Check if all expected categories are present
                missing_categories = [cat for cat in expected_categories if cat not in categories]
                
                if not missing_categories:
                    self.log_result("Technician Categories", True, 
                                  f"All {len(categories)} MSP categories present: {', '.join(categories)}")
                else:
                    self.log_result("Technician Categories", False, 
                                  f"Missing categories: {', '.join(missing_categories)}")
                
                # Verify description mentions MSP
                if 'MSP' in description:
                    self.log_result("Technician Categories Description", True, 
                                  f"Description correctly mentions MSP: {description}")
                else:
                    self.log_result("Technician Categories Description", False, 
                                  f"Description should mention MSP: {description}")
            else:
                self.log_result("Technician Categories", False, "Response missing 'categories' field")
        else:
            self.log_result("Technician Categories", False, 
                          f"Failed to get technician categories: {response.status_code if response else 'No response'}")
    
    def test_asset_types(self):
        """Test 8: GET /api/asset-types - Should return list of asset types"""
        print("\n=== Testing Asset Types ===")
        
        response = self.make_request('GET', '/asset-types')
        if response and response.status_code == 200:
            asset_types_result = response.json()
            
            # Check response structure
            if 'asset_types' in asset_types_result:
                asset_types = asset_types_result.get('asset_types', [])
                description = asset_types_result.get('description', '')
                
                # Expected MSP asset types
                expected_types = ['Server', 'Network Device', 'Database', 'Application', 'Storage', 
                                'Cloud Resource', 'Virtual Machine', 'Container', 'Load Balancer', 'Firewall']
                
                # Check if most expected types are present (allow some flexibility)
                present_types = [asset_type for asset_type in expected_types if asset_type in asset_types]
                
                if len(present_types) >= 8:  # At least 8 out of 10 expected types
                    self.log_result("Asset Types", True, 
                                  f"{len(asset_types)} asset types present, including: {', '.join(present_types[:5])}...")
                else:
                    missing_types = [asset_type for asset_type in expected_types if asset_type not in asset_types]
                    self.log_result("Asset Types", False, 
                                  f"Missing many expected types: {', '.join(missing_types)}")
                
                # Verify description mentions MSP
                if 'MSP' in description:
                    self.log_result("Asset Types Description", True, 
                                  f"Description correctly mentions MSP: {description}")
                else:
                    self.log_result("Asset Types Description", False, 
                                  f"Description should mention MSP: {description}")
            else:
                self.log_result("Asset Types", False, "Response missing 'asset_types' field")
        else:
            self.log_result("Asset Types", False, 
                          f"Failed to get asset types: {response.status_code if response else 'No response'}")
    
    def run_all_tests(self):
        """Run all demo mode and auto-correlation tests"""
        print("🚀 Starting Demo Mode and Auto-Correlation Feature Tests")
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
        print("\n" + "="*80)
        print("🎯 DEMO MODE & AUTO-CORRELATION TEST SUMMARY")
        print("="*80)
        
        passed = sum(1 for result in self.test_results if result['success'])
        total = len(self.test_results)
        success_rate = (passed / total * 100) if total > 0 else 0
        
        print(f"📊 Overall Results: {passed}/{total} tests passed ({success_rate:.1f}% success rate)")
        
        # Group results by category
        categories = {
            "Demo Mode": [],
            "Auto-Correlation": [],
            "MSP Categories": []
        }
        
        for result in self.test_results:
            test_name = result['test']
            if 'Demo' in test_name:
                categories["Demo Mode"].append(result)
            elif 'Auto-Correlation' in test_name:
                categories["Auto-Correlation"].append(result)
            else:
                categories["MSP Categories"].append(result)
        
        for category, results in categories.items():
            if results:
                passed_cat = sum(1 for r in results if r['success'])
                total_cat = len(results)
                print(f"\n📋 {category}: {passed_cat}/{total_cat} passed")
                
                for result in results:
                    status = "✅" if result['success'] else "❌"
                    print(f"  {status} {result['test']}")
        
        # Print any failures with details
        failures = [r for r in self.test_results if not r['success']]
        if failures:
            print(f"\n❌ Failed Tests ({len(failures)}):")
            for failure in failures:
                print(f"  • {failure['test']}: {failure['message']}")
                if failure.get('details'):
                    print(f"    Details: {failure['details']}")
        
        print("\n" + "="*80)

if __name__ == "__main__":
    tester = DemoAutoCorrelationTester()
    tester.run_all_tests()