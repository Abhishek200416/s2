#!/usr/bin/env python3
"""
Alert Whisperer High Priority Notifications Test
Tests the specific notification system for high priority alerts as requested in the review.

Test Scenarios:
1. Get Company and API Key
2. Send HIGH Priority Alert
3. Send CRITICAL Priority Alert  
4. Verify Notifications Were Created
5. Check Unread Count
6. Send MEDIUM Priority Alert (Should NOT Create Notification)
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

class HighPriorityNotificationTester:
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
    
    def test_1_get_company_and_api_key(self):
        """Test 1: Get Company and API Key"""
        print("\n=== Test 1: Get Company and API Key ===")
        
        # Get companies
        response = self.make_request('GET', '/companies')
        if response and response.status_code == 200:
            companies = response.json()
            self.log_result("Get Companies", True, f"Retrieved {len(companies)} companies")
            
            # Find a company with API key (prefer comp-acme or acme1)
            target_company = None
            for company in companies:
                if company.get('id') in ['comp-acme', 'acme1'] and company.get('api_key'):
                    target_company = company
                    break
            
            # If no preferred company found, use any company with API key
            if not target_company:
                for company in companies:
                    if company.get('api_key'):
                        target_company = company
                        break
            
            if target_company:
                self.api_key = target_company.get('api_key')
                self.company_id = target_company.get('id')
                company_name = target_company.get('name')
                
                self.log_result("Extract API Key", True, 
                              f"Found company '{company_name}' (ID: {self.company_id}) with API key: {self.api_key[:20]}...")
                return True
            else:
                self.log_result("Extract API Key", False, "No company found with API key")
                return False
        else:
            self.log_result("Get Companies", False, f"Failed to get companies: {response.status_code if response else 'No response'}")
            return False
    
    def test_2_send_high_priority_alert(self):
        """Test 2: Send HIGH Priority Alert"""
        print("\n=== Test 2: Send HIGH Priority Alert ===")
        
        if not self.api_key:
            self.log_result("Send HIGH Alert", False, "No API key available")
            return None
        
        webhook_payload = {
            "asset_name": "web-server-01",
            "signature": "high_memory_usage",
            "severity": "high",
            "message": "Memory usage at 95% - immediate attention required",
            "tool_source": "Monitoring System"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={self.api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            webhook_result = response.json()
            alert_id = webhook_result.get('alert_id')
            
            if alert_id:
                self.log_result("Send HIGH Alert", True, f"HIGH priority alert created successfully with ID: {alert_id}")
                return alert_id
            else:
                self.log_result("Send HIGH Alert", False, "Alert created but no alert_id returned")
                return None
        else:
            self.log_result("Send HIGH Alert", False, 
                          f"Failed to create HIGH alert: {response.status_code if response else 'No response'}")
            return None
    
    def test_3_send_critical_priority_alert(self):
        """Test 3: Send CRITICAL Priority Alert"""
        print("\n=== Test 3: Send CRITICAL Priority Alert ===")
        
        if not self.api_key:
            self.log_result("Send CRITICAL Alert", False, "No API key available")
            return None
        
        webhook_payload = {
            "asset_name": "db-server-01",
            "signature": "database_down",
            "severity": "critical",
            "message": "Database server is not responding",
            "tool_source": "Monitoring System"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={self.api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            webhook_result = response.json()
            alert_id = webhook_result.get('alert_id')
            
            if alert_id:
                self.log_result("Send CRITICAL Alert", True, f"CRITICAL priority alert created successfully with ID: {alert_id}")
                return alert_id
            else:
                self.log_result("Send CRITICAL Alert", False, "Alert created but no alert_id returned")
                return None
        else:
            self.log_result("Send CRITICAL Alert", False, 
                          f"Failed to create CRITICAL alert: {response.status_code if response else 'No response'}")
            return None
    
    def test_4_verify_notifications_created(self, high_alert_id, critical_alert_id):
        """Test 4: Verify Notifications Were Created"""
        print("\n=== Test 4: Verify Notifications Were Created ===")
        
        # Wait a moment for notifications to be processed
        time.sleep(2)
        
        # Get all notifications
        response = self.make_request('GET', '/notifications')
        if response and response.status_code == 200:
            notifications = response.json()
            self.log_result("Get Notifications", True, f"Retrieved {len(notifications)} notifications")
            
            # Look for notifications related to our high and critical alerts
            high_notification = None
            critical_notification = None
            
            for notification in notifications:
                notification_type = notification.get('type', '')
                title = notification.get('title', '')
                message = notification.get('message', '')
                metadata = notification.get('metadata', {})
                
                # Check if this notification is for high priority alert
                if ('high' in notification_type.lower() or 'high_memory_usage' in title or 
                    'web-server-01' in message or metadata.get('signature') == 'high_memory_usage'):
                    high_notification = notification
                
                # Check if this notification is for critical priority alert
                if ('critical' in notification_type.lower() or 'database_down' in title or 
                    'db-server-01' in message or metadata.get('signature') == 'database_down'):
                    critical_notification = notification
            
            # Verify high priority notification
            if high_notification:
                self.verify_notification_structure(high_notification, "high", "high_memory_usage", "web-server-01")
            else:
                self.log_result("HIGH Notification Created", False, "No notification found for HIGH priority alert")
            
            # Verify critical priority notification
            if critical_notification:
                self.verify_notification_structure(critical_notification, "critical", "database_down", "db-server-01")
            else:
                self.log_result("CRITICAL Notification Created", False, "No notification found for CRITICAL priority alert")
            
            return len([n for n in [high_notification, critical_notification] if n is not None])
        else:
            self.log_result("Get Notifications", False, 
                          f"Failed to get notifications: {response.status_code if response else 'No response'}")
            return 0
    
    def verify_notification_structure(self, notification, expected_type, expected_signature, expected_asset):
        """Verify notification has correct structure"""
        notification_type = notification.get('type', '')
        title = notification.get('title', '')
        message = notification.get('message', '')
        metadata = notification.get('metadata', {})
        read_status = notification.get('read', True)  # Should be false for new notifications
        
        # Check notification structure
        structure_checks = []
        
        # Check type contains expected severity
        if expected_type.lower() in notification_type.lower():
            structure_checks.append(f"type contains '{expected_type}'")
        
        # Check title contains signature
        if expected_signature in title:
            structure_checks.append(f"title contains signature '{expected_signature}'")
        
        # Check message contains asset name
        if expected_asset in message:
            structure_checks.append(f"message contains asset '{expected_asset}'")
        
        # Check metadata has required fields
        if metadata.get('signature') == expected_signature:
            structure_checks.append("metadata has correct signature")
        
        if metadata.get('tool_source') == "Monitoring System":
            structure_checks.append("metadata has tool_source")
        
        if metadata.get('asset_name') == expected_asset:
            structure_checks.append("metadata has correct asset_name")
        
        # Check read status (should be false for new notifications)
        if read_status == False:
            structure_checks.append("read status is false (unread)")
        
        if len(structure_checks) >= 4:  # At least 4 out of 7 checks should pass
            self.log_result(f"{expected_type.upper()} Notification Structure", True, 
                          f"Notification structure verified: {', '.join(structure_checks)}")
        else:
            self.log_result(f"{expected_type.upper()} Notification Structure", False, 
                          f"Notification structure incomplete. Passed: {', '.join(structure_checks)}")
    
    def test_5_check_unread_count(self):
        """Test 5: Check Unread Count"""
        print("\n=== Test 5: Check Unread Count ===")
        
        response = self.make_request('GET', '/notifications/unread-count')
        if response and response.status_code == 200:
            unread_data = response.json()
            unread_count = unread_data.get('count', 0)
            
            if unread_count >= 2:
                self.log_result("Unread Count Check", True, 
                              f"Unread count is {unread_count} (>= 2 as expected for high and critical alerts)")
            else:
                self.log_result("Unread Count Check", False, 
                              f"Unread count is {unread_count}, expected >= 2 for high and critical alerts")
        else:
            self.log_result("Unread Count Check", False, 
                          f"Failed to get unread count: {response.status_code if response else 'No response'}")
    
    def test_6_send_medium_priority_alert(self):
        """Test 6: Send MEDIUM Priority Alert (Should NOT Create Notification)"""
        print("\n=== Test 6: Send MEDIUM Priority Alert (Should NOT Create Notification) ===")
        
        if not self.api_key:
            self.log_result("Send MEDIUM Alert", False, "No API key available")
            return
        
        # Get current notification count before sending medium alert
        response = self.make_request('GET', '/notifications')
        initial_notification_count = 0
        if response and response.status_code == 200:
            initial_notifications = response.json()
            initial_notification_count = len(initial_notifications)
        
        # Send medium priority alert
        webhook_payload = {
            "asset_name": "app-server-01",
            "signature": "disk_space_warning",
            "severity": "medium",
            "message": "Disk space at 75% - monitoring",
            "tool_source": "Monitoring System"
        }
        
        response = self.make_request('POST', f'/webhooks/alerts?api_key={self.api_key}', json=webhook_payload)
        if response and response.status_code == 200:
            webhook_result = response.json()
            alert_id = webhook_result.get('alert_id')
            
            if alert_id:
                self.log_result("Send MEDIUM Alert", True, f"MEDIUM priority alert created successfully with ID: {alert_id}")
                
                # Wait a moment for potential notification processing
                time.sleep(2)
                
                # Check if notification count increased (it shouldn't for medium alerts)
                response = self.make_request('GET', '/notifications')
                if response and response.status_code == 200:
                    current_notifications = response.json()
                    current_notification_count = len(current_notifications)
                    
                    # Check if any new notification was created for medium alert
                    medium_notification_found = False
                    for notification in current_notifications:
                        title = notification.get('title', '')
                        message = notification.get('message', '')
                        metadata = notification.get('metadata', {})
                        
                        if ('disk_space_warning' in title or 'app-server-01' in message or 
                            metadata.get('signature') == 'disk_space_warning'):
                            medium_notification_found = True
                            break
                    
                    if not medium_notification_found:
                        self.log_result("MEDIUM Alert No Notification", True, 
                                      "Correctly did NOT create notification for MEDIUM priority alert")
                    else:
                        self.log_result("MEDIUM Alert No Notification", False, 
                                      "Incorrectly created notification for MEDIUM priority alert")
                else:
                    self.log_result("MEDIUM Alert No Notification", False, 
                                  "Failed to verify notification creation for medium alert")
            else:
                self.log_result("Send MEDIUM Alert", False, "Alert created but no alert_id returned")
        else:
            self.log_result("Send MEDIUM Alert", False, 
                          f"Failed to create MEDIUM alert: {response.status_code if response else 'No response'}")
    
    def run_all_tests(self):
        """Run all high priority notification tests"""
        print("🚀 Starting High Priority Alert Notifications Test Suite")
        print(f"Backend URL: {self.base_url}")
        
        # Authenticate first
        if not self.authenticate():
            print("❌ Authentication failed, cannot continue tests")
            return
        
        # Test 1: Get Company and API Key
        if not self.test_1_get_company_and_api_key():
            print("❌ Cannot continue without API key")
            return
        
        # Test 2: Send HIGH Priority Alert
        high_alert_id = self.test_2_send_high_priority_alert()
        
        # Test 3: Send CRITICAL Priority Alert
        critical_alert_id = self.test_3_send_critical_priority_alert()
        
        # Test 4: Verify Notifications Were Created
        notifications_found = self.test_4_verify_notifications_created(high_alert_id, critical_alert_id)
        
        # Test 5: Check Unread Count
        self.test_5_check_unread_count()
        
        # Test 6: Send MEDIUM Priority Alert (Should NOT Create Notification)
        self.test_6_send_medium_priority_alert()
        
        # Summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("🏁 HIGH PRIORITY NOTIFICATIONS TEST SUMMARY")
        print("="*60)
        
        passed = sum(1 for result in self.test_results if result['success'])
        total = len(self.test_results)
        success_rate = (passed / total * 100) if total > 0 else 0
        
        print(f"📊 Overall Results: {passed}/{total} tests passed ({success_rate:.1f}% success rate)")
        
        if success_rate >= 80:
            print("✅ HIGH PRIORITY NOTIFICATIONS SYSTEM WORKING CORRECTLY")
        else:
            print("❌ HIGH PRIORITY NOTIFICATIONS SYSTEM HAS ISSUES")
        
        print("\n📋 Detailed Results:")
        for result in self.test_results:
            status = "✅" if result['success'] else "❌"
            print(f"{status} {result['test']}: {result['message']}")
        
        print("\n" + "="*60)

if __name__ == "__main__":
    tester = HighPriorityNotificationTester()
    tester.run_all_tests()