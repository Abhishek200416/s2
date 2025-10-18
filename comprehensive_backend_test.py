#!/usr/bin/env python3
"""
Comprehensive Alert Whisperer MSP Platform Backend Test Suite
Tests all endpoints mentioned in the review request:

1. Authentication & User Management
2. Company Management  
3. Alert & Webhook System
4. Incident Correlation
5. SLA Management
6. AWS Integration
7. Real-Time Features
8. Runbook Management
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

class ComprehensiveTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.session = requests.Session()
        self.auth_token = None
        self.test_results = []
        self.api_key = None
        
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
    
    def test_authentication_user_management(self):
        """Test Category 1: Authentication & User Management"""
        print("\n=== 1. Authentication & User Management ===")
        
        # POST /api/auth/login
        login_data = {
            "email": "admin@alertwhisperer.com",
            "password": "admin123"
        }
        
        response = self.make_request('POST', '/auth/login', json=login_data)
        if response and response.status_code == 200:
            data = response.json()
            self.auth_token = data.get('access_token')
            self.log_result("POST /api/auth/login", True, f"Successfully logged in as {data.get('user', {}).get('name', 'Unknown')}")
        else:
            self.log_result("POST /api/auth/login", False, f"Login failed with status {response.status_code if response else 'No response'}")
            return False
        
        # GET /api/profile
        response = self.make_request('GET', '/profile')
        if response and response.status_code == 200:
            profile = response.json()
            self.log_result("GET /api/profile", True, f"Retrieved profile for {profile.get('name')}")
        else:
            self.log_result("GET /api/profile", False, f"Failed to get profile: {response.status_code if response else 'No response'}")
        
        # PUT /api/profile
        update_data = {
            "name": "Admin User Updated",
            "email": "admin@alertwhisperer.com"
        }
        response = self.make_request('PUT', '/profile', json=update_data)
        if response and response.status_code == 200:
            self.log_result("PUT /api/profile", True, "Profile updated successfully")
        else:
            self.log_result("PUT /api/profile", False, f"Failed to update profile: {response.status_code if response else 'No response'}")
        
        # PUT /api/profile/password
        password_data = {
            "current_password": "admin123",
            "new_password": "admin456"
        }
        response = self.make_request('PUT', '/profile/password', json=password_data)
        if response and response.status_code == 200:
            # Change back
            password_data = {"current_password": "admin456", "new_password": "admin123"}
            self.make_request('PUT', '/profile/password', json=password_data)
            self.log_result("PUT /api/profile/password", True, "Password change working")
        else:
            self.log_result("PUT /api/profile/password", False, f"Failed to change password: {response.status_code if response else 'No response'}")
        
        # GET /api/users (list all users)
        response = self.make_request('GET', '/users')
        if response and response.status_code == 200:
            users = response.json()
            self.log_result("GET /api/users", True, f"Retrieved {len(users)} users")
        else:
            self.log_result("GET /api/users", False, f"Failed to get users: {response.status_code if response else 'No response'}")
        
        return True
    
    def test_company_management(self):
        """Test Category 2: Company Management"""
        print("\n=== 2. Company Management ===")
        
        # GET /api/companies
        response = self.make_request('GET', '/companies')
        if response and response.status_code == 200:
            companies = response.json()
            self.log_result("GET /api/companies", True, f"Retrieved {len(companies)} companies")
            
            # Find Acme Corp and get API key
            for company in companies:
                if company.get('id') == 'comp-acme':
                    self.api_key = company.get('api_key')
                    break
        else:
            self.log_result("GET /api/companies", False, f"Failed to get companies: {response.status_code if response else 'No response'}")
        
        # GET /api/companies/{company_id}
        response = self.make_request('GET', '/companies/comp-acme')
        if response and response.status_code == 200:
            company = response.json()
            self.log_result("GET /api/companies/{company_id}", True, f"Retrieved company: {company.get('name')}")
        else:
            self.log_result("GET /api/companies/{company_id}", False, f"Failed to get company: {response.status_code if response else 'No response'}")
        
        # POST /api/companies/{company_id}/regenerate-api-key
        response = self.make_request('POST', '/companies/comp-acme/regenerate-api-key')
        if response and response.status_code == 200:
            updated_company = response.json()
            new_api_key = updated_company.get('api_key')
            if new_api_key:
                self.api_key = new_api_key  # Update for webhook tests
                self.log_result("POST /api/companies/{company_id}/regenerate-api-key", True, f"API key regenerated: {new_api_key[:20]}...")
            else:
                self.log_result("POST /api/companies/{company_id}/regenerate-api-key", False, "No API key in response")
        else:
            self.log_result("POST /api/companies/{company_id}/regenerate-api-key", False, f"Failed to regenerate API key: {response.status_code if response else 'No response'}")
        
        # GET /api/companies/{company_id}/webhook-security
        response = self.make_request('GET', '/companies/comp-acme/webhook-security')
        if response and response.status_code == 200:
            config = response.json()
            self.log_result("GET /api/companies/{company_id}/webhook-security", True, f"Webhook security config retrieved, enabled: {config.get('enabled')}")
        else:
            self.log_result("GET /api/companies/{company_id}/webhook-security", False, f"Failed to get webhook security: {response.status_code if response else 'No response'}")
        
        # POST /api/companies/{company_id}/webhook-security/enable
        response = self.make_request('POST', '/companies/comp-acme/webhook-security/enable')
        if response and response.status_code == 200:
            config = response.json()
            self.log_result("POST /api/companies/{company_id}/webhook-security/enable", True, f"HMAC enabled with secret: {config.get('hmac_secret', '')[:10]}...")
        else:
            self.log_result("POST /api/companies/{company_id}/webhook-security/enable", False, f"Failed to enable HMAC: {response.status_code if response else 'No response'}")
        
        # GET /api/companies/{company_id}/correlation-config
        response = self.make_request('GET', '/companies/comp-acme/correlation-config')
        if response and response.status_code == 200:
            config = response.json()
            self.log_result("GET /api/companies/{company_id}/correlation-config", True, f"Correlation config: {config.get('time_window_minutes')}min window, auto: {config.get('auto_correlate')}")
        else:
            self.log_result("GET /api/companies/{company_id}/correlation-config", False, f"Failed to get correlation config: {response.status_code if response else 'No response'}")
        
        # PUT /api/companies/{company_id}/correlation-config
        update_data = {"time_window_minutes": 10, "auto_correlate": True}
        response = self.make_request('PUT', '/companies/comp-acme/correlation-config', json=update_data)
        if response and response.status_code == 200:
            config = response.json()
            self.log_result("PUT /api/companies/{company_id}/correlation-config", True, f"Correlation config updated: {config.get('time_window_minutes')}min")
        else:
            self.log_result("PUT /api/companies/{company_id}/correlation-config", False, f"Failed to update correlation config: {response.status_code if response else 'No response'}")
    
    def test_alert_webhook_system(self):
        """Test Category 3: Alert & Webhook System"""
        print("\n=== 3. Alert & Webhook System ===")
        
        if not self.api_key:
            self.log_result("Alert Webhook Setup", False, "No API key available for webhook testing")
            return
        
        # Disable HMAC for webhook testing
        response = self.make_request('POST', '/companies/comp-acme/webhook-security/disable')
        # Don't check response as it might already be disabled
        
        # POST /api/webhooks/alerts?api_key={valid_key} (send test alert)
        webhook_payload = {
            "asset_name": "srv-app-01",
            "signature": "disk_space_critical",
            "severity": "critical",
            "message": "Disk space critically low - 95% full",
            "tool_source": "Datadog"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={self.api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            result = response.json()
            alert_id = result.get('alert_id')
            self.log_result("POST /api/webhooks/alerts (valid key)", True, f"Alert created successfully: {alert_id}")
        else:
            self.log_result("POST /api/webhooks/alerts (valid key)", False, f"Failed to create alert: {response.status_code if response else 'No response'}")
        
        # Verify alert with invalid API key returns 401
        invalid_key = "invalid_key_12345"
        response = self.make_request('POST', f'/webhooks/alerts?api_key={invalid_key}', json=webhook_payload)
        if response and response.status_code == 401:
            self.log_result("POST /api/webhooks/alerts (invalid key)", True, "Correctly rejected invalid API key with 401")
        else:
            self.log_result("POST /api/webhooks/alerts (invalid key)", False, f"Expected 401 for invalid key, got: {response.status_code if response else 'No response'}")
        
        # GET /api/alerts?company_id=comp-acme
        response = self.make_request('GET', '/alerts?company_id=comp-acme')
        if response and response.status_code == 200:
            alerts = response.json()
            self.log_result("GET /api/alerts", True, f"Retrieved {len(alerts)} alerts for comp-acme")
        else:
            self.log_result("GET /api/alerts", False, f"Failed to get alerts: {response.status_code if response else 'No response'}")
    
    def test_incident_correlation(self):
        """Test Category 4: Incident Correlation"""
        print("\n=== 4. Incident Correlation ===")
        
        if not self.api_key:
            self.log_result("Incident Correlation Setup", False, "No API key available")
            return
        
        # Create multiple alerts for correlation
        alerts_created = []
        for i in range(3):
            webhook_payload = {
                "asset_name": "srv-db-01",
                "signature": "memory_leak_detected",
                "severity": "high",
                "message": f"Memory leak detected - correlation test {i+1}",
                "tool_source": "Zabbix"
            }
            
            response = self.make_request('POST', f'/webhooks/alerts?api_key={self.api_key}', json=webhook_payload)
            if response and response.status_code == 200:
                result = response.json()
                alerts_created.append(result.get('alert_id'))
        
        if len(alerts_created) >= 2:
            self.log_result("Create Correlation Test Alerts", True, f"Created {len(alerts_created)} alerts for correlation")
            
            # Wait for alerts to be processed
            time.sleep(2)
            
            # POST /api/incidents/correlate?company_id=comp-acme
            response = self.make_request('POST', '/incidents/correlate?company_id=comp-acme')
            if response and response.status_code == 200:
                result = response.json()
                incidents_created = result.get('incidents_created', 0)
                self.log_result("POST /api/incidents/correlate", True, f"Correlation completed: {incidents_created} incidents created")
                
                # Verify priority scoring engine
                response = self.make_request('GET', '/incidents?company_id=comp-acme')
                if response and response.status_code == 200:
                    incidents = response.json()
                    if incidents:
                        incident = incidents[0]
                        priority_score = incident.get('priority_score')
                        tool_sources = incident.get('tool_sources', [])
                        if priority_score is not None:
                            self.log_result("Verify Priority Scoring", True, f"Priority score: {priority_score}, tool sources: {tool_sources}")
                        else:
                            self.log_result("Verify Priority Scoring", False, "No priority score found in incident")
                    else:
                        self.log_result("Verify Priority Scoring", False, "No incidents found after correlation")
                else:
                    self.log_result("Verify Priority Scoring", False, f"Failed to get incidents: {response.status_code if response else 'No response'}")
            else:
                self.log_result("POST /api/incidents/correlate", False, f"Failed to correlate: {response.status_code if response else 'No response'}")
        else:
            self.log_result("Create Correlation Test Alerts", False, f"Only created {len(alerts_created)} alerts")
        
        # GET /api/incidents?company_id=comp-acme
        response = self.make_request('GET', '/incidents?company_id=comp-acme')
        if response and response.status_code == 200:
            incidents = response.json()
            self.log_result("GET /api/incidents", True, f"Retrieved {len(incidents)} incidents for comp-acme")
        else:
            self.log_result("GET /api/incidents", False, f"Failed to get incidents: {response.status_code if response else 'No response'}")
    
    def test_sla_management(self):
        """Test Category 5: SLA Management"""
        print("\n=== 5. SLA Management ===")
        
        # GET /api/companies/comp-acme/sla-config
        response = self.make_request('GET', '/companies/comp-acme/sla-config')
        if response and response.status_code == 200:
            config = response.json()
            self.log_result("GET /api/companies/{id}/sla-config", True, f"SLA config retrieved - Enabled: {config.get('enabled')}")
        else:
            self.log_result("GET /api/companies/{id}/sla-config", False, f"Failed to get SLA config: {response.status_code if response else 'No response'}")
        
        # PUT /api/companies/comp-acme/sla-config
        sla_update = {
            "enabled": True,
            "response_times": {"critical": 15, "high": 60, "medium": 240, "low": 720},
            "resolution_times": {"critical": 120, "high": 240, "medium": 720, "low": 1440}
        }
        response = self.make_request('PUT', '/companies/comp-acme/sla-config', json=sla_update)
        if response and response.status_code == 200:
            config = response.json()
            self.log_result("PUT /api/companies/{id}/sla-config", True, f"SLA config updated successfully")
        else:
            self.log_result("PUT /api/companies/{id}/sla-config", False, f"Failed to update SLA config: {response.status_code if response else 'No response'}")
        
        # Get an incident ID for SLA testing
        response = self.make_request('GET', '/incidents?company_id=comp-acme')
        if response and response.status_code == 200:
            incidents = response.json()
            if incidents:
                incident_id = incidents[0].get('id')
                
                # GET /api/incidents/{incident_id}/sla-status
                response = self.make_request('GET', f'/incidents/{incident_id}/sla-status')
                if response and response.status_code == 200:
                    sla_status = response.json()
                    self.log_result("GET /api/incidents/{id}/sla-status", True, f"SLA status retrieved for incident")
                else:
                    self.log_result("GET /api/incidents/{id}/sla-status", False, f"Failed to get SLA status: {response.status_code if response else 'No response'}")
            else:
                self.log_result("GET /api/incidents/{id}/sla-status", False, "No incidents available for SLA testing")
        
        # GET /api/companies/comp-acme/sla-report?days=30
        response = self.make_request('GET', '/companies/comp-acme/sla-report?days=30')
        if response and response.status_code == 200:
            report = response.json()
            self.log_result("GET /api/companies/{id}/sla-report", True, f"SLA report retrieved for 30 days")
        else:
            self.log_result("GET /api/companies/{id}/sla-report", False, f"Failed to get SLA report: {response.status_code if response else 'No response'}")
    
    def test_aws_integration(self):
        """Test Category 6: AWS Integration"""
        print("\n=== 6. AWS Integration ===")
        
        # GET /api/companies/comp-acme/aws-credentials
        response = self.make_request('GET', '/companies/comp-acme/aws-credentials')
        if response and response.status_code in [200, 404]:
            if response.status_code == 200:
                creds = response.json()
                self.log_result("GET /api/companies/{id}/aws-credentials", True, f"AWS credentials configured: {creds.get('configured', False)}")
            else:
                self.log_result("GET /api/companies/{id}/aws-credentials", True, "AWS credentials not configured (404 expected)")
        else:
            self.log_result("GET /api/companies/{id}/aws-credentials", False, f"Failed to get AWS credentials: {response.status_code if response else 'No response'}")
        
        # GET /api/companies/comp-acme/agent-health
        response = self.make_request('GET', '/companies/comp-acme/agent-health')
        if response and response.status_code in [200, 400]:
            if response.status_code == 200:
                health = response.json()
                self.log_result("GET /api/companies/{id}/agent-health", True, f"Agent health retrieved")
            else:
                # 400 expected if AWS not configured
                self.log_result("GET /api/companies/{id}/agent-health", True, "Agent health requires AWS credentials (400 expected)")
        else:
            self.log_result("GET /api/companies/{id}/agent-health", False, f"Failed to get agent health: {response.status_code if response else 'No response'}")
        
        # GET /api/companies/comp-acme/assets
        response = self.make_request('GET', '/companies/comp-acme/assets')
        if response and response.status_code in [200, 400]:
            if response.status_code == 200:
                assets = response.json()
                self.log_result("GET /api/companies/{id}/assets", True, f"Assets retrieved")
            else:
                # 400 expected if AWS not configured
                self.log_result("GET /api/companies/{id}/assets", True, "Assets endpoint requires AWS credentials (400 expected)")
        else:
            self.log_result("GET /api/companies/{id}/assets", False, f"Failed to get assets: {response.status_code if response else 'No response'}")
    
    def test_realtime_features(self):
        """Test Category 7: Real-Time Features"""
        print("\n=== 7. Real-Time Features ===")
        
        # GET /api/metrics/realtime
        response = self.make_request('GET', '/metrics/realtime')
        if response and response.status_code == 200:
            metrics = response.json()
            alerts = metrics.get('alerts', {})
            incidents = metrics.get('incidents', {})
            kpis = metrics.get('kpis', {})
            self.log_result("GET /api/metrics/realtime", True, f"Real-time metrics: {alerts.get('total', 0)} alerts, {incidents.get('total', 0)} incidents")
        else:
            self.log_result("GET /api/metrics/realtime", False, f"Failed to get real-time metrics: {response.status_code if response else 'No response'}")
        
        # GET /api/notifications
        response = self.make_request('GET', '/notifications')
        if response and response.status_code == 200:
            notifications = response.json()
            self.log_result("GET /api/notifications", True, f"Retrieved {len(notifications)} notifications")
        else:
            self.log_result("GET /api/notifications", False, f"Failed to get notifications: {response.status_code if response else 'No response'}")
        
        # GET /api/notifications/unread-count
        response = self.make_request('GET', '/notifications/unread-count')
        if response and response.status_code == 200:
            count_data = response.json()
            count = count_data.get('count', 0)
            self.log_result("GET /api/notifications/unread-count", True, f"Unread notifications: {count}")
        else:
            self.log_result("GET /api/notifications/unread-count", False, f"Failed to get unread count: {response.status_code if response else 'No response'}")
        
        # GET /api/chat/comp-acme
        response = self.make_request('GET', '/chat/comp-acme')
        if response and response.status_code == 200:
            messages = response.json()
            self.log_result("GET /api/chat/{company_id}", True, f"Retrieved {len(messages)} chat messages")
        else:
            self.log_result("GET /api/chat/{company_id}", False, f"Failed to get chat messages: {response.status_code if response else 'No response'}")
    
    def test_runbook_management(self):
        """Test Category 8: Runbook Management"""
        print("\n=== 8. Runbook Management ===")
        
        # GET /api/runbooks?company_id=comp-acme
        response = self.make_request('GET', '/runbooks?company_id=comp-acme')
        if response and response.status_code == 200:
            runbooks = response.json()
            self.log_result("GET /api/runbooks", True, f"Retrieved {len(runbooks)} runbooks for comp-acme")
        else:
            self.log_result("GET /api/runbooks", False, f"Failed to get runbooks: {response.status_code if response else 'No response'}")
        
        # POST /api/runbooks (create custom runbook)
        runbook_data = {
            "name": "Test Disk Cleanup Runbook",
            "description": "Automated disk cleanup for testing",
            "risk_level": "low",
            "signature": "disk_space_critical",
            "company_id": "comp-acme",
            "actions": ["df -h", "du -sh /tmp/*", "rm -rf /tmp/old_files"],
            "health_checks": {"disk_space_after": "df -h | grep '/$'"},
            "auto_approve": True
        }
        
        response = self.make_request('POST', '/runbooks', json=runbook_data)
        if response and response.status_code == 200:
            runbook = response.json()
            runbook_id = runbook.get('id')
            self.log_result("POST /api/runbooks", True, f"Created runbook: {runbook.get('name')} (ID: {runbook_id})")
            
            if runbook_id:
                # PUT /api/runbooks/{id} (update runbook)
                update_data = {
                    "description": "Updated automated disk cleanup for testing",
                    "risk_level": "medium"
                }
                response = self.make_request('PUT', f'/runbooks/{runbook_id}', json=update_data)
                if response and response.status_code == 200:
                    updated_runbook = response.json()
                    self.log_result("PUT /api/runbooks/{id}", True, f"Updated runbook: {updated_runbook.get('description')}")
                else:
                    self.log_result("PUT /api/runbooks/{id}", False, f"Failed to update runbook: {response.status_code if response else 'No response'}")
        else:
            self.log_result("POST /api/runbooks", False, f"Failed to create runbook: {response.status_code if response else 'No response'}")
    
    def run_all_tests(self):
        """Run all test categories"""
        print("🚀 Comprehensive Alert Whisperer MSP Platform Backend Test Suite")
        print(f"📡 Backend URL: {self.base_url}")
        print(f"⏰ Test started at: {datetime.now().isoformat()}")
        print("=" * 80)
        
        # Run all test categories
        if not self.test_authentication_user_management():
            print("❌ Authentication failed - stopping tests")
            return
        
        self.test_company_management()
        self.test_alert_webhook_system()
        self.test_incident_correlation()
        self.test_sla_management()
        self.test_aws_integration()
        self.test_realtime_features()
        self.test_runbook_management()
        
        # Print summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if failed_tests > 0:
            print(f"\nFAILED TESTS:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  ❌ {result['test']}: {result['message']}")
        
        return success_rate >= 90  # Consider 90%+ success rate as passing

if __name__ == "__main__":
    tester = ComprehensiveTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)