#!/usr/bin/env python3
"""
Alert Whisperer Backend API Test Suite - Real-Time Features Testing
Tests new real-time features: fake alert generator removal, real-time metrics, 
chat system, notifications, enhanced correlation with priority scoring
"""

import requests
import json
import sys
import os
from datetime import datetime
import time

# Get backend URL from frontend .env file
BACKEND_URL = "https://api-integration-26.preview.emergentagent.com/api"

class AlertWhispererTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.session = requests.Session()
        self.auth_token = None
        self.test_results = []
        
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
    
    def test_authentication(self):
        """Test 1: Authentication & Profile Management"""
        print("\n=== Testing Authentication & Profile Management ===")
        
        # Test login
        login_data = {
            "email": "admin@alertwhisperer.com",
            "password": "admin123"
        }
        
        response = self.make_request('POST', '/auth/login', json=login_data)
        if response is None:
            self.log_result("Login", False, "Request failed - backend not accessible")
            return False
            
        if response.status_code == 200:
            data = response.json()
            self.auth_token = data.get('access_token')
            self.log_result("Login", True, f"Successfully logged in as {data.get('user', {}).get('name', 'Unknown')}")
        else:
            self.log_result("Login", False, f"Login failed with status {response.status_code}", response.text)
            return False
        
        # Test get profile
        response = self.make_request('GET', '/profile')
        if response and response.status_code == 200:
            profile = response.json()
            self.log_result("Get Profile", True, f"Retrieved profile for {profile.get('name')}")
        else:
            self.log_result("Get Profile", False, f"Failed to get profile: {response.status_code if response else 'No response'}")
        
        # Test update profile
        update_data = {
            "name": "Admin User Updated",
            "email": "admin@alertwhisperer.com"
        }
        response = self.make_request('PUT', '/profile', json=update_data)
        if response and response.status_code == 200:
            updated_profile = response.json()
            if updated_profile.get('name') == "Admin User Updated":
                self.log_result("Update Profile", True, "Profile name updated successfully")
            else:
                self.log_result("Update Profile", False, "Profile update didn't reflect changes")
        else:
            self.log_result("Update Profile", False, f"Failed to update profile: {response.status_code if response else 'No response'}")
        
        # Test password change (admin123 -> admin456 -> admin123)
        password_data = {
            "current_password": "admin123",
            "new_password": "admin456"
        }
        response = self.make_request('PUT', '/profile/password', json=password_data)
        if response and response.status_code == 200:
            self.log_result("Change Password (Step 1)", True, "Password changed from admin123 to admin456")
            
            # Change back to original
            password_data = {
                "current_password": "admin456",
                "new_password": "admin123"
            }
            response = self.make_request('PUT', '/profile/password', json=password_data)
            if response and response.status_code == 200:
                self.log_result("Change Password (Step 2)", True, "Password changed back to admin123")
            else:
                self.log_result("Change Password (Step 2)", False, f"Failed to change password back: {response.status_code if response else 'No response'}")
        else:
            self.log_result("Change Password (Step 1)", False, f"Failed to change password: {response.status_code if response else 'No response'}")
        
        return True
    
    def test_company_api_keys(self):
        """Test 2: Company & API Key Management"""
        print("\n=== Testing Company & API Key Management ===")
        
        # Test get all companies
        response = self.make_request('GET', '/companies')
        if response and response.status_code == 200:
            companies = response.json()
            self.log_result("Get Companies", True, f"Retrieved {len(companies)} companies")
            
            # Find Acme Corp
            acme_company = None
            for company in companies:
                if company.get('id') == 'comp-acme':
                    acme_company = company
                    break
            
            if acme_company:
                self.log_result("Find Acme Corp", True, f"Found Acme Corp with API key: {acme_company.get('api_key', 'None')[:20]}...")
                
                # Test get specific company
                response = self.make_request('GET', '/companies/comp-acme')
                if response and response.status_code == 200:
                    company_detail = response.json()
                    original_api_key = company_detail.get('api_key')
                    self.log_result("Get Specific Company", True, f"Retrieved Acme Corp details, API key exists: {bool(original_api_key)}")
                    
                    # Test regenerate API key
                    response = self.make_request('POST', '/companies/comp-acme/regenerate-api-key')
                    if response and response.status_code == 200:
                        updated_company = response.json()
                        new_api_key = updated_company.get('api_key')
                        if new_api_key and new_api_key != original_api_key:
                            self.log_result("Regenerate API Key", True, f"API key regenerated successfully (changed from {original_api_key[:10]}... to {new_api_key[:10]}...)")
                            return new_api_key  # Return for webhook testing
                        else:
                            self.log_result("Regenerate API Key", False, "API key didn't change after regeneration")
                    else:
                        self.log_result("Regenerate API Key", False, f"Failed to regenerate API key: {response.status_code if response else 'No response'}")
                else:
                    self.log_result("Get Specific Company", False, f"Failed to get company details: {response.status_code if response else 'No response'}")
            else:
                self.log_result("Find Acme Corp", False, "Acme Corp (comp-acme) not found in companies list")
        else:
            self.log_result("Get Companies", False, f"Failed to get companies: {response.status_code if response else 'No response'}")
        
        return None
    
    def test_webhook_integration(self, api_key=None):
        """Test 3: Webhook Integration"""
        print("\n=== Testing Webhook Integration ===")
        
        if not api_key:
            # Try to get API key from companies endpoint
            response = self.make_request('GET', '/companies/comp-acme')
            if response and response.status_code == 200:
                company = response.json()
                api_key = company.get('api_key')
        
        if not api_key:
            self.log_result("Webhook Setup", False, "No API key available for webhook testing")
            return
        
        # Test webhook with valid API key
        webhook_payload = {
            "asset_name": "srv-app-01",
            "signature": "service_down:nginx",
            "severity": "high",
            "message": "Nginx service test alert",
            "tool_source": "TestMonitor"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            webhook_result = response.json()
            alert_id = webhook_result.get('alert_id')
            self.log_result("Webhook Valid API Key", True, f"Alert created successfully with ID: {alert_id}")
            
            # Verify alert was created by checking alerts endpoint
            response = self.make_request('GET', '/alerts?company_id=comp-acme&status=active')
            if response and response.status_code == 200:
                alerts = response.json()
                found_alert = any(alert.get('id') == alert_id for alert in alerts)
                if found_alert:
                    self.log_result("Verify Alert Created", True, "Alert found in active alerts list")
                else:
                    self.log_result("Verify Alert Created", False, "Alert not found in active alerts list")
            else:
                self.log_result("Verify Alert Created", False, f"Failed to retrieve alerts: {response.status_code if response else 'No response'}")
        else:
            self.log_result("Webhook Valid API Key", False, f"Webhook failed with valid API key: {response.status_code if response else 'No response'}")
        
        # Test webhook with invalid API key
        invalid_api_key = "invalid_key_12345"
        response = self.make_request('POST', f'/webhooks/alerts?api_key={invalid_api_key}', json=webhook_payload)
        if response is not None and response.status_code == 401:
            self.log_result("Webhook Invalid API Key", True, "Correctly rejected invalid API key with 401 error")
        elif response is not None:
            self.log_result("Webhook Invalid API Key", False, f"Expected 401 for invalid API key, got: {response.status_code}")
        else:
            self.log_result("Webhook Invalid API Key", False, "No response received for invalid API key test")
    
    def test_fake_generator_removed(self):
        """Test 4: Verify Fake Alert Generator Removed"""
        print("\n=== Testing Fake Alert Generator Removal ===")
        
        # Test that fake alert generator endpoint returns 404
        response = self.make_request('POST', '/alerts/generate')
        if response is not None and response.status_code == 404:
            self.log_result("Fake Generator Removed", True, "POST /api/alerts/generate correctly returns 404")
        elif response is not None:
            self.log_result("Fake Generator Removed", False, f"Expected 404 for fake generator, got: {response.status_code}")
        else:
            self.log_result("Fake Generator Removed", False, "No response received for fake generator test")
    
    def test_realtime_metrics(self):
        """Test 5: Real-Time Metrics Endpoint"""
        print("\n=== Testing Real-Time Metrics Endpoint ===")
        
        # Test real-time metrics endpoint
        response = self.make_request('GET', '/metrics/realtime')
        if response and response.status_code == 200:
            metrics = response.json()
            
            # Check required fields
            required_fields = ['alerts', 'incidents', 'kpis', 'timestamp']
            missing_fields = [field for field in required_fields if field not in metrics]
            
            if not missing_fields:
                # Check alert counts structure
                alerts = metrics.get('alerts', {})
                alert_fields = ['critical', 'high', 'medium', 'low', 'total']
                alert_missing = [field for field in alert_fields if field not in alerts]
                
                # Check incident counts structure
                incidents = metrics.get('incidents', {})
                incident_fields = ['new', 'in_progress', 'resolved', 'escalated', 'total']
                incident_missing = [field for field in incident_fields if field not in incidents]
                
                # Check KPIs structure
                kpis = metrics.get('kpis', {})
                kpi_fields = ['noise_reduction_pct', 'self_healed_count', 'mttr_minutes']
                kpi_missing = [field for field in kpi_fields if field not in kpis]
                
                if not alert_missing and not incident_missing and not kpi_missing:
                    self.log_result("Real-Time Metrics", True, f"Metrics endpoint working: {alerts['total']} alerts, {incidents['total']} incidents, {kpis['noise_reduction_pct']:.1f}% noise reduction")
                else:
                    missing_all = alert_missing + incident_missing + kpi_missing
                    self.log_result("Real-Time Metrics", False, f"Missing metric fields: {missing_all}")
            else:
                self.log_result("Real-Time Metrics", False, f"Missing required fields: {missing_fields}")
        else:
            self.log_result("Real-Time Metrics", False, f"Failed to get metrics: {response.status_code if response else 'No response'}")
    
    def test_chat_system(self):
        """Test 6: Chat System"""
        print("\n=== Testing Chat System ===")
        
        # Test get chat messages
        response = self.make_request('GET', '/chat/comp-acme')
        if response and response.status_code == 200:
            messages = response.json()
            self.log_result("Get Chat Messages", True, f"Retrieved {len(messages)} chat messages for Acme Corp")
            
            # Test send chat message
            test_message = {"message": "Test message from backend testing"}
            response = self.make_request('POST', '/chat/comp-acme', json=test_message)
            if response and response.status_code == 200:
                sent_message = response.json()
                if sent_message.get('message') == "Test message from backend testing":
                    self.log_result("Send Chat Message", True, f"Message sent successfully by {sent_message.get('user_name')}")
                    
                    # Test mark messages as read
                    response = self.make_request('PUT', '/chat/comp-acme/mark-read')
                    if response and response.status_code == 200:
                        self.log_result("Mark Chat Read", True, "Messages marked as read successfully")
                    else:
                        self.log_result("Mark Chat Read", False, f"Failed to mark messages as read: {response.status_code if response else 'No response'}")
                else:
                    self.log_result("Send Chat Message", False, "Message content doesn't match what was sent")
            else:
                self.log_result("Send Chat Message", False, f"Failed to send message: {response.status_code if response else 'No response'}")
        else:
            self.log_result("Get Chat Messages", False, f"Failed to get chat messages: {response.status_code if response else 'No response'}")
    
    def test_notification_system(self):
        """Test 7: Notification System"""
        print("\n=== Testing Notification System ===")
        
        # Test get all notifications
        response = self.make_request('GET', '/notifications')
        if response and response.status_code == 200:
            notifications = response.json()
            self.log_result("Get Notifications", True, f"Retrieved {len(notifications)} notifications")
            
            # Test get unread count
            response = self.make_request('GET', '/notifications/unread-count')
            if response and response.status_code == 200:
                unread_data = response.json()
                unread_count = unread_data.get('count', 0)
                self.log_result("Get Unread Count", True, f"Unread notifications count: {unread_count}")
                
                # If there are notifications, test marking one as read
                if len(notifications) > 0:
                    first_notification = notifications[0]
                    notification_id = first_notification.get('id')
                    if notification_id:
                        response = self.make_request('PUT', f'/notifications/{notification_id}/read')
                        if response and response.status_code == 200:
                            self.log_result("Mark Notification Read", True, f"Notification {notification_id[:8]}... marked as read")
                        else:
                            self.log_result("Mark Notification Read", False, f"Failed to mark notification as read: {response.status_code if response else 'No response'}")
                    else:
                        self.log_result("Mark Notification Read", False, "No notification ID found to test marking as read")
                else:
                    self.log_result("Mark Notification Read", True, "No notifications to mark as read (expected)")
            else:
                self.log_result("Get Unread Count", False, f"Failed to get unread count: {response.status_code if response else 'No response'}")
        else:
            self.log_result("Get Notifications", False, f"Failed to get notifications: {response.status_code if response else 'No response'}")
    
    def test_enhanced_correlation(self, api_key=None):
        """Test 8: Enhanced Correlation with Priority Scoring"""
        print("\n=== Testing Enhanced Correlation with Priority Scoring ===")
        
        if not api_key:
            # Get API key from companies endpoint
            response = self.make_request('GET', '/companies/comp-acme')
            if response and response.status_code == 200:
                company = response.json()
                api_key = company.get('api_key')
        
        if not api_key:
            self.log_result("Enhanced Correlation Setup", False, "No API key available for correlation testing")
            return
        
        # First, create a test alert via webhook
        webhook_payload = {
            "asset_name": "srv-app-01",
            "signature": "high_cpu",
            "severity": "critical",
            "message": "CPU usage 95% - correlation test",
            "tool_source": "Datadog"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            webhook_result = response.json()
            alert_id = webhook_result.get('alert_id')
            self.log_result("Create Test Alert", True, f"Test alert created with ID: {alert_id}")
            
            # Wait a moment for the alert to be processed
            time.sleep(1)
            
            # Now correlate alerts
            response = self.make_request('POST', '/incidents/correlate?company_id=comp-acme')
            if response and response.status_code == 200:
                correlation_result = response.json()
                incidents_created = correlation_result.get('incidents_created', 0)
                self.log_result("Correlate Alerts", True, f"Correlation completed: {incidents_created} incidents created")
                
                # Check if incidents have priority scores and tool sources
                response = self.make_request('GET', '/incidents?company_id=comp-acme')
                if response and response.status_code == 200:
                    incidents = response.json()
                    
                    # Find our test incident
                    test_incident = None
                    for incident in incidents:
                        if incident.get('signature') == 'high_cpu' and incident.get('asset_name') == 'srv-app-01':
                            test_incident = incident
                            break
                    
                    if test_incident:
                        priority_score = test_incident.get('priority_score')
                        tool_sources = test_incident.get('tool_sources', [])
                        
                        if priority_score is not None and tool_sources:
                            self.log_result("Priority Scoring", True, f"Incident has priority_score: {priority_score}, tool_sources: {tool_sources}")
                        else:
                            missing = []
                            if priority_score is None:
                                missing.append("priority_score")
                            if not tool_sources:
                                missing.append("tool_sources")
                            self.log_result("Priority Scoring", False, f"Incident missing: {missing}")
                    else:
                        self.log_result("Priority Scoring", False, "Test incident not found after correlation")
                else:
                    self.log_result("Priority Scoring", False, f"Failed to get incidents: {response.status_code if response else 'No response'}")
            else:
                self.log_result("Correlate Alerts", False, f"Failed to correlate alerts: {response.status_code if response else 'No response'}")
        else:
            self.log_result("Create Test Alert", False, f"Failed to create test alert: {response.status_code if response else 'No response'}")
    
    def test_webhook_realtime_broadcasting(self, api_key=None):
        """Test 9: Webhook Real-Time Broadcasting Structure"""
        print("\n=== Testing Webhook Real-Time Broadcasting ===")
        
        if not api_key:
            # Get API key from companies endpoint
            response = self.make_request('GET', '/companies/comp-acme')
            if response and response.status_code == 200:
                company = response.json()
                api_key = company.get('api_key')
        
        if not api_key:
            self.log_result("Webhook Broadcasting Setup", False, "No API key available for webhook broadcasting test")
            return
        
        # Send another alert via webhook to test broadcasting structure
        webhook_payload = {
            "asset_name": "srv-app-01",
            "signature": "memory_leak",
            "severity": "high",
            "message": "Memory usage increasing - broadcasting test",
            "tool_source": "Zabbix"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            webhook_result = response.json()
            alert_id = webhook_result.get('alert_id')
            message = webhook_result.get('message')
            
            if alert_id and message:
                self.log_result("Webhook Broadcasting", True, f"Webhook response includes alert_id: {alert_id}")
                
                # Verify alert is stored in database
                response = self.make_request('GET', f'/alerts?company_id=comp-acme')
                if response and response.status_code == 200:
                    alerts = response.json()
                    found_alert = any(alert.get('id') == alert_id for alert in alerts)
                    if found_alert:
                        self.log_result("Alert Storage", True, "Alert confirmed stored in database")
                    else:
                        self.log_result("Alert Storage", False, "Alert not found in database")
                else:
                    self.log_result("Alert Storage", False, f"Failed to verify alert storage: {response.status_code if response else 'No response'}")
            else:
                missing = []
                if not alert_id:
                    missing.append("alert_id")
                if not message:
                    missing.append("message")
                self.log_result("Webhook Broadcasting", False, f"Webhook response missing: {missing}")
        else:
            self.log_result("Webhook Broadcasting", False, f"Failed to send webhook alert: {response.status_code if response else 'No response'}")
    
    def test_existing_features(self):
        """Test 10: Existing Features (smoke test)"""
        print("\n=== Testing Existing Features (Smoke Test) ===")
        
        # Test seed endpoint
        response = self.make_request('POST', '/seed')
        if response and response.status_code == 200:
            seed_result = response.json()
            self.log_result("Database Seed", True, f"Database reinitialized: {seed_result.get('companies', 0)} companies, {seed_result.get('users', 0)} users")
        else:
            self.log_result("Database Seed", False, f"Failed to seed database: {response.status_code if response else 'No response'}")
        
        # Test get alerts
        response = self.make_request('GET', '/alerts?company_id=comp-acme&status=active')
        if response and response.status_code == 200:
            alerts = response.json()
            self.log_result("Get Alerts", True, f"Retrieved {len(alerts)} active alerts for Acme Corp")
        else:
            self.log_result("Get Alerts", False, f"Failed to get alerts: {response.status_code if response else 'No response'}")
    
    def run_all_tests(self):
        """Run all test scenarios for real-time Alert Whisperer features"""
        print(f"Starting Alert Whisperer Real-Time Features Backend API Tests")
        print(f"Backend URL: {self.base_url}")
        print("=" * 80)
        
        # Test 1: Authentication & Profile Management
        auth_success = self.test_authentication()
        
        if not auth_success:
            print("\n❌ Authentication failed - skipping remaining tests")
            return self.generate_summary()
        
        # Test 2: Company & API Key Management
        api_key = self.test_company_api_keys()
        
        # Test 3: Webhook Integration (Original)
        self.test_webhook_integration(api_key)
        
        # Test 4: Verify Fake Alert Generator Removed
        self.test_fake_generator_removed()
        
        # Test 5: Real-Time Metrics Endpoint
        self.test_realtime_metrics()
        
        # Test 6: Chat System
        self.test_chat_system()
        
        # Test 7: Notification System
        self.test_notification_system()
        
        # Test 8: Enhanced Correlation with Priority Scoring
        self.test_enhanced_correlation(api_key)
        
        # Test 9: Webhook Real-Time Broadcasting
        self.test_webhook_realtime_broadcasting(api_key)
        
        # Test 10: Existing Features (Smoke Test)
        self.test_existing_features()
        
        return self.generate_summary()
    
    def generate_summary(self):
        """Generate test summary"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%" if total_tests > 0 else "0%")
        
        if failed_tests > 0:
            print("\nFAILED TESTS:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  ❌ {result['test']}: {result['message']}")
        
        return {
            'total': total_tests,
            'passed': passed_tests,
            'failed': failed_tests,
            'results': self.test_results
        }

if __name__ == "__main__":
    tester = AlertWhispererTester()
    summary = tester.run_all_tests()
    
    # Exit with error code if tests failed
    if summary['failed'] > 0:
        sys.exit(1)
    else:
        print("\n🎉 All tests passed!")
        sys.exit(0)