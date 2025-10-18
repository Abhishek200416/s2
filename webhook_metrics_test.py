#!/usr/bin/env python3
"""
Alert Whisperer - Webhook and Before-After Metrics Test
Tests the specific endpoints requested in the review:
1. Get API Key for Testing
2. Test Webhook with Asset Auto-Creation
3. Verify Asset Was Created
4. Test Before-After Metrics Endpoint
5. Send Another Alert for Same Asset (Idempotency)
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

class WebhookMetricsTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.session = requests.Session()
        self.auth_token = None
        self.test_results = []
        self.api_key = None
        self.company_id = None
        
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
        """Authenticate to get access token"""
        print("=== Authenticating ===")
        
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
    
    def test_1_get_api_key(self):
        """Test 1: Get API Key for Testing"""
        print("\n=== Test 1: Get API Key for Testing ===")
        
        # GET /api/companies to get a company
        response = self.make_request('GET', '/companies')
        if response and response.status_code == 200:
            companies = response.json()
            self.log_result("Get Companies", True, f"Retrieved {len(companies)} companies")
            
            # Look for comp-acme or first available company
            target_company = None
            for company in companies:
                if company.get('id') == 'comp-acme':
                    target_company = company
                    break
            
            if not target_company and companies:
                target_company = companies[0]
            
            if target_company:
                self.company_id = target_company.get('id')
                self.api_key = target_company.get('api_key')
                
                if self.api_key:
                    self.log_result("Extract API Key", True, f"Found company {self.company_id} with API key: {self.api_key[:20]}...")
                    return True
                else:
                    self.log_result("Extract API Key", False, f"Company {self.company_id} has no API key")
                    return False
            else:
                self.log_result("Extract API Key", False, "No companies found")
                return False
        else:
            self.log_result("Get Companies", False, f"Failed to get companies: {response.status_code if response else 'No response'}")
            return False
    
    def test_2_webhook_asset_auto_creation(self):
        """Test 2: Test Webhook with Asset Auto-Creation"""
        print("\n=== Test 2: Test Webhook with Asset Auto-Creation ===")
        
        if not self.api_key:
            self.log_result("Webhook Setup", False, "No API key available for webhook testing")
            return False
        
        # POST /api/webhooks/alerts?api_key={API_KEY}
        webhook_payload = {
            "asset_name": "server-01",
            "signature": "high_cpu_usage",
            "severity": "high",
            "message": "CPU usage above 90%",
            "tool_source": "Monitoring System"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={self.api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            webhook_result = response.json()
            alert_id = webhook_result.get('alert_id')
            message = webhook_result.get('message')
            
            if alert_id:
                self.log_result("Webhook Alert Creation", True, f"Alert created successfully with ID: {alert_id}")
                self.alert_id = alert_id
                return True
            else:
                self.log_result("Webhook Alert Creation", False, f"Webhook response missing alert_id: {webhook_result}")
                return False
        else:
            self.log_result("Webhook Alert Creation", False, f"Webhook failed: {response.status_code if response else 'No response'}")
            if response:
                try:
                    error_detail = response.json()
                    print(f"   Error details: {error_detail}")
                except:
                    print(f"   Response text: {response.text}")
            return False
    
    def test_3_verify_asset_created(self):
        """Test 3: Verify Asset Was Created"""
        print("\n=== Test 3: Verify Asset Was Created ===")
        
        if not self.company_id:
            self.log_result("Asset Verification Setup", False, "No company ID available")
            return False
        
        # GET /api/companies/{company_id} to check if "server-01" asset exists in assets array
        response = self.make_request('GET', f'/companies/{self.company_id}')
        if response and response.status_code == 200:
            company = response.json()
            assets = company.get('assets', [])
            
            # Look for server-01 asset
            server_01_asset = None
            for asset in assets:
                if asset.get('name') == 'server-01' or asset.get('asset_name') == 'server-01':
                    server_01_asset = asset
                    break
            
            if server_01_asset:
                self.log_result("Asset Auto-Creation", True, f"Asset 'server-01' was auto-created: {server_01_asset}")
                return True
            else:
                # Check if assets array exists but is empty or doesn't contain our asset
                self.log_result("Asset Auto-Creation", False, f"Asset 'server-01' not found in company assets. Assets found: {[asset.get('name', asset.get('asset_name', 'unnamed')) for asset in assets]}")
                return False
        else:
            self.log_result("Asset Auto-Creation", False, f"Failed to get company details: {response.status_code if response else 'No response'}")
            return False
    
    def test_4_before_after_metrics(self):
        """Test 4: Test Before-After Metrics Endpoint"""
        print("\n=== Test 4: Test Before-After Metrics Endpoint ===")
        
        if not self.company_id:
            self.log_result("Metrics Setup", False, "No company ID available")
            return False
        
        # GET /api/metrics/before-after?company_id={company_id}
        response = self.make_request('GET', f'/metrics/before-after?company_id={self.company_id}')
        if response and response.status_code == 200:
            metrics = response.json()
            
            # Verify response has required structure
            required_sections = ['baseline', 'current', 'improvements', 'summary']
            missing_sections = [section for section in required_sections if section not in metrics]
            
            if not missing_sections:
                # Check baseline structure
                baseline = metrics.get('baseline', {})
                baseline_fields = ['incidents_count', 'noise_reduction_pct', 'self_healed_pct', 'mttr_minutes']
                baseline_missing = [field for field in baseline_fields if field not in baseline]
                
                # Check current structure
                current = metrics.get('current', {})
                current_fields = ['incidents_count', 'noise_reduction_pct', 'self_healed_pct', 'self_healed_count', 'mttr_minutes']
                current_missing = [field for field in current_fields if field not in current]
                
                # Check improvements structure
                improvements = metrics.get('improvements', {})
                improvements_fields = ['noise_reduction', 'self_healed', 'mttr']
                improvements_missing = [field for field in improvements_fields if field not in improvements]
                
                # Check summary structure
                summary = metrics.get('summary', {})
                summary_fields = ['incidents_prevented', 'auto_resolved_count', 'time_saved_per_incident', 'noise_reduced']
                summary_missing = [field for field in summary_fields if field not in summary]
                
                all_missing = baseline_missing + current_missing + improvements_missing + summary_missing
                
                if not all_missing:
                    self.log_result("Before-After Metrics Structure", True, 
                                  f"Metrics endpoint has correct structure - Baseline: {baseline['incidents_count']} incidents, Current: {current['incidents_count']} incidents, Noise reduction: {improvements['noise_reduction']}%")
                    
                    # Log detailed metrics for verification
                    print(f"   Baseline: incidents={baseline['incidents_count']}, noise_reduction={baseline['noise_reduction_pct']}%, self_healed={baseline['self_healed_pct']}%, mttr={baseline['mttr_minutes']}min")
                    print(f"   Current: incidents={current['incidents_count']}, noise_reduction={current['noise_reduction_pct']}%, self_healed={current['self_healed_pct']}%, mttr={current['mttr_minutes']}min")
                    print(f"   Improvements: noise_reduction={improvements['noise_reduction']}%, self_healed={improvements['self_healed']}%, mttr={improvements['mttr']}%")
                    print(f"   Summary: incidents_prevented={summary['incidents_prevented']}, auto_resolved={summary['auto_resolved_count']}, time_saved={summary['time_saved_per_incident']}min, noise_reduced={summary['noise_reduced']}%")
                    
                    return True
                else:
                    self.log_result("Before-After Metrics Structure", False, f"Missing required fields: {all_missing}")
                    return False
            else:
                self.log_result("Before-After Metrics Structure", False, f"Missing required sections: {missing_sections}")
                return False
        else:
            self.log_result("Before-After Metrics", False, f"Failed to get before-after metrics: {response.status_code if response else 'No response'}")
            if response:
                try:
                    error_detail = response.json()
                    print(f"   Error details: {error_detail}")
                except:
                    print(f"   Response text: {response.text}")
            return False
    
    def test_5_webhook_idempotency(self):
        """Test 5: Send Another Alert for Same Asset (Idempotency Test)"""
        print("\n=== Test 5: Send Another Alert for Same Asset (Idempotency Test) ===")
        
        if not self.api_key:
            self.log_result("Idempotency Setup", False, "No API key available for idempotency testing")
            return False
        
        # POST /api/webhooks/alerts?api_key={API_KEY} with same payload as Test 2
        webhook_payload = {
            "asset_name": "server-01",
            "signature": "high_cpu_usage",
            "severity": "high",
            "message": "CPU usage above 90%",
            "tool_source": "Monitoring System"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={self.api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            webhook_result = response.json()
            alert_id = webhook_result.get('alert_id')
            message = webhook_result.get('message')
            duplicate = webhook_result.get('duplicate', False)
            
            if alert_id:
                if duplicate:
                    self.log_result("Webhook Idempotency", True, f"Idempotency working - duplicate detected: {duplicate}, alert_id: {alert_id}")
                else:
                    self.log_result("Webhook Idempotency", True, f"Alert created successfully (no asset creation needed this time): {alert_id}")
                return True
            else:
                self.log_result("Webhook Idempotency", False, f"Webhook response missing alert_id: {webhook_result}")
                return False
        else:
            self.log_result("Webhook Idempotency", False, f"Webhook failed: {response.status_code if response else 'No response'}")
            if response:
                try:
                    error_detail = response.json()
                    print(f"   Error details: {error_detail}")
                except:
                    print(f"   Response text: {response.text}")
            return False
    
    def run_all_tests(self):
        """Run all tests in sequence"""
        print(f"🚀 Starting Alert Whisperer Webhook & Metrics Tests")
        print(f"Backend URL: {self.base_url}")
        print("=" * 80)
        
        # Authenticate first
        if not self.authenticate():
            print("❌ Authentication failed - cannot proceed with tests")
            return
        
        # Run tests in sequence
        tests = [
            self.test_1_get_api_key,
            self.test_2_webhook_asset_auto_creation,
            self.test_3_verify_asset_created,
            self.test_4_before_after_metrics,
            self.test_5_webhook_idempotency
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"❌ Test {test.__name__} failed with exception: {e}")
        
        # Print summary
        print("\n" + "=" * 80)
        print(f"🏁 TEST SUMMARY: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
        
        if passed == total:
            print("✅ ALL TESTS PASSED - Webhook and Before-After Metrics endpoints working correctly!")
        else:
            print(f"❌ {total - passed} tests failed - see details above")
        
        # Print detailed results
        print("\n📊 DETAILED RESULTS:")
        for result in self.test_results:
            status = "✅" if result["success"] else "❌"
            print(f"{status} {result['test']}: {result['message']}")
        
        return passed == total

if __name__ == "__main__":
    tester = WebhookMetricsTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)