#!/usr/bin/env python3
"""
MSP-Focused Improvements Test Suite - Corrected Version
Tests the specific endpoints mentioned in the review request with correct API expectations
"""

import requests
import json
import sys
import os
from datetime import datetime
import time

# Get backend URL from frontend .env file
BACKEND_URL = "https://incident-portal.preview.emergentagent.com/api"

class MSPTester:
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
    
    def authenticate(self):
        """Authenticate and get token"""
        login_data = {
            "email": "admin@alertwhisperer.com",
            "password": "admin123"
        }
        
        response = self.make_request('POST', '/auth/login', json=login_data)
        if response and response.status_code == 200:
            data = response.json()
            self.auth_token = data.get('access_token')
            self.log_result("Authentication", True, f"Successfully logged in as {data.get('user', {}).get('name', 'Unknown')}")
            return True
        else:
            self.log_result("Authentication", False, f"Login failed with status {response.status_code if response else 'No response'}")
            return False
    
    def test_aws_credentials_management(self):
        """Test AWS Credentials Management endpoints"""
        print("\n=== Testing AWS Credentials Management ===")
        
        # Test 1: GET /api/companies/comp-acme/aws-credentials (should return not configured initially)
        response = self.make_request('GET', '/companies/comp-acme/aws-credentials')
        if response and response.status_code == 200:
            config = response.json()
            configured = config.get('configured', True)  # Default to True to check if it's actually False
            
            if not configured:
                self.log_result("AWS Credentials - Initial GET (not configured)", True, "GET /api/companies/comp-acme/aws-credentials correctly returns configured=false when not set")
            else:
                # If already configured, delete first for clean testing
                delete_response = self.make_request('DELETE', '/companies/comp-acme/aws-credentials')
                if delete_response and delete_response.status_code == 200:
                    self.log_result("AWS Credentials - Cleanup", True, "Existing AWS credentials deleted for clean testing")
                    # Test again
                    response = self.make_request('GET', '/companies/comp-acme/aws-credentials')
                    if response and response.status_code == 200:
                        config = response.json()
                        if not config.get('configured', True):
                            self.log_result("AWS Credentials - Initial GET (not configured)", True, "GET returns configured=false after cleanup")
                        else:
                            self.log_result("AWS Credentials - Initial GET (not configured)", False, f"Still shows configured=true after cleanup: {config}")
                    else:
                        self.log_result("AWS Credentials - Initial GET (not configured)", False, f"Failed to get config after cleanup: {response.status_code if response else 'No response'}")
                else:
                    self.log_result("AWS Credentials - Cleanup", False, f"Failed to delete existing credentials: {delete_response.status_code if delete_response else 'No response'}")
        else:
            self.log_result("AWS Credentials - Initial GET (not configured)", False, f"Failed to get AWS credentials config: {response.status_code if response else 'No response'}")
        
        # Test 2: POST /api/companies/comp-acme/aws-credentials with credentials
        aws_credentials = {
            "access_key_id": "AKIATEST123",
            "secret_access_key": "test_secret_key_123",
            "region": "us-east-1"
        }
        
        response = self.make_request('POST', '/companies/comp-acme/aws-credentials', json=aws_credentials)
        if response and response.status_code == 200:
            created_result = response.json()
            message = created_result.get('message')
            region = created_result.get('region')
            encrypted = created_result.get('encrypted')
            
            if message and region == "us-east-1" and encrypted:
                self.log_result("AWS Credentials - Create", True, f"AWS credentials created successfully: {message}, region={region}, encrypted={encrypted}")
            else:
                self.log_result("AWS Credentials - Create", False, f"Unexpected response structure: {created_result}")
        else:
            self.log_result("AWS Credentials - Create", False, f"Failed to create AWS credentials: {response.status_code if response else 'No response'}")
        
        # Test 3: GET /api/companies/comp-acme/aws-credentials (should now return configured=true)
        response = self.make_request('GET', '/companies/comp-acme/aws-credentials')
        if response and response.status_code == 200:
            retrieved_config = response.json()
            configured = retrieved_config.get('configured')
            region = retrieved_config.get('region')
            access_key_preview = retrieved_config.get('access_key_id_preview')
            
            if configured and region == "us-east-1" and access_key_preview:
                self.log_result("AWS Credentials - Retrieve Configured", True, f"AWS credentials configured: region={region}, access_key_preview={access_key_preview}")
            else:
                self.log_result("AWS Credentials - Retrieve Configured", False, f"Unexpected config after creation: {retrieved_config}")
        else:
            self.log_result("AWS Credentials - Retrieve Configured", False, f"Failed to retrieve AWS credentials: {response.status_code if response else 'No response'}")
        
        # Test 4: POST /api/companies/comp-acme/aws-credentials/test (should test AWS connection)
        response = self.make_request('POST', '/companies/comp-acme/aws-credentials/test')
        if response and response.status_code == 200:
            test_result = response.json()
            
            # Since we're using test credentials, this should fail but return proper structure
            if 'verified' in test_result:
                verified = test_result.get('verified')
                self.log_result("AWS Credentials - Test Connection", True, f"AWS connection test completed: verified={verified} (expected to fail with test credentials)")
            else:
                self.log_result("AWS Credentials - Test Connection", False, f"AWS connection test missing 'verified' field: {test_result}")
        else:
            self.log_result("AWS Credentials - Test Connection", False, f"Failed to test AWS connection: {response.status_code if response else 'No response'}")
        
        # Test 5: DELETE /api/companies/comp-acme/aws-credentials (should remove credentials)
        response = self.make_request('DELETE', '/companies/comp-acme/aws-credentials')
        if response and response.status_code == 200:
            delete_result = response.json()
            message = delete_result.get('message')
            
            if message:
                self.log_result("AWS Credentials - Delete", True, f"AWS credentials deleted successfully: {message}")
                
                # Verify deletion by checking config again
                verify_response = self.make_request('GET', '/companies/comp-acme/aws-credentials')
                if verify_response and verify_response.status_code == 200:
                    config = verify_response.json()
                    if not config.get('configured', True):
                        self.log_result("AWS Credentials - Verify Deletion", True, "AWS credentials successfully deleted (configured=false)")
                    else:
                        self.log_result("AWS Credentials - Verify Deletion", False, f"AWS credentials may not be deleted: {config}")
                else:
                    self.log_result("AWS Credentials - Verify Deletion", False, f"Failed to verify deletion: {verify_response.status_code if verify_response else 'No response'}")
            else:
                self.log_result("AWS Credentials - Delete", False, f"Delete response missing message: {delete_result}")
        else:
            self.log_result("AWS Credentials - Delete", False, f"Failed to delete AWS credentials: {response.status_code if response else 'No response'}")
    
    def test_on_call_scheduling(self):
        """Test On-Call Scheduling endpoints"""
        print("\n=== Testing On-Call Scheduling ===")
        
        # Test 1: GET /api/users (to get technician IDs)
        response = self.make_request('GET', '/users')
        if response and response.status_code == 200:
            users = response.json()
            technician_users = [user for user in users if user.get('role') in ['technician', 'admin']]
            
            if len(technician_users) > 0:
                technician_id = technician_users[0].get('id')
                technician_name = technician_users[0].get('name')
                self.log_result("On-Call - Get Users", True, f"Retrieved {len(users)} users, found technician: {technician_name} (ID: {technician_id})")
            else:
                self.log_result("On-Call - Get Users", False, "No technicians found in users list")
                return
        else:
            self.log_result("On-Call - Get Users", False, f"Failed to get users: {response.status_code if response else 'No response'}")
            return
        
        # Test 2: POST /api/on-call-schedules with schedule data
        schedule_data = {
            "name": "Test Daily Schedule",
            "technician_id": technician_id,
            "schedule_type": "daily",
            "start_time": "2025-01-15T09:00:00",
            "end_time": "2025-01-15T17:00:00",
            "priority": 1,
            "description": "Test on-call schedule for MSP testing"
        }
        
        response = self.make_request('POST', '/on-call-schedules', json=schedule_data)
        if response and response.status_code == 200:
            created_schedule = response.json()
            schedule_id = created_schedule.get('id')
            schedule_name = created_schedule.get('name')
            
            if schedule_id and schedule_name == "Test Daily Schedule":
                self.log_result("On-Call - Create Schedule", True, f"On-call schedule created: {schedule_name} (ID: {schedule_id})")
            else:
                self.log_result("On-Call - Create Schedule", False, f"Schedule created but missing expected data: {created_schedule}")
                return
        else:
            self.log_result("On-Call - Create Schedule", False, f"Failed to create on-call schedule: {response.status_code if response else 'No response'}")
            return
        
        # Test 3: GET /api/on-call-schedules (should return all schedules)
        response = self.make_request('GET', '/on-call-schedules')
        if response and response.status_code == 200:
            schedules = response.json()
            found_schedule = any(schedule.get('id') == schedule_id for schedule in schedules)
            
            if found_schedule:
                self.log_result("On-Call - Get All Schedules", True, f"Retrieved {len(schedules)} schedules, found our test schedule")
            else:
                self.log_result("On-Call - Get All Schedules", False, "Test schedule not found in schedules list")
        else:
            self.log_result("On-Call - Get All Schedules", False, f"Failed to get schedules: {response.status_code if response else 'No response'}")
        
        # Test 4: GET /api/on-call-schedules/current (should return current on-call technician)
        response = self.make_request('GET', '/on-call-schedules/current')
        if response and response.status_code == 200:
            current_schedule = response.json()
            if current_schedule and current_schedule.get('technician_id'):
                current_tech_id = current_schedule.get('technician_id')
                current_schedule_name = current_schedule.get('name')
                self.log_result("On-Call - Get Current Schedule", True, f"Current on-call: {current_schedule_name} (Technician: {current_tech_id})")
            else:
                self.log_result("On-Call - Get Current Schedule", True, "No current on-call schedule (expected if outside schedule time)")
        elif response and response.status_code == 404:
            self.log_result("On-Call - Get Current Schedule", True, "No current on-call schedule (404 - expected if no active schedule)")
        else:
            self.log_result("On-Call - Get Current Schedule", False, f"Failed to get current schedule: {response.status_code if response else 'No response'}")
        
        # Test 5: PUT /api/on-call-schedules/{id} (update schedule)
        update_data = {
            "name": "Updated Test Schedule",
            "priority": 2,
            "description": "Updated description for MSP testing"
        }
        
        response = self.make_request('PUT', f'/on-call-schedules/{schedule_id}', json=update_data)
        if response and response.status_code == 200:
            updated_schedule = response.json()
            updated_name = updated_schedule.get('name')
            updated_priority = updated_schedule.get('priority')
            
            if updated_name == "Updated Test Schedule" and updated_priority == 2:
                self.log_result("On-Call - Update Schedule", True, f"Schedule updated successfully: {updated_name}, priority={updated_priority}")
            else:
                self.log_result("On-Call - Update Schedule", False, f"Schedule update didn't apply correctly: name={updated_name}, priority={updated_priority}")
        else:
            self.log_result("On-Call - Update Schedule", False, f"Failed to update schedule: {response.status_code if response else 'No response'}")
        
        # Test 6: DELETE /api/on-call-schedules/{id} (delete schedule)
        response = self.make_request('DELETE', f'/on-call-schedules/{schedule_id}')
        if response and response.status_code == 200:
            delete_result = response.json()
            message = delete_result.get('message')
            
            if message:
                self.log_result("On-Call - Delete Schedule", True, f"Schedule deleted successfully: {message}")
                
                # Verify deletion by trying to GET the specific schedule (should return 404)
                verify_response = self.make_request('GET', f'/on-call-schedules/{schedule_id}')
                if verify_response and verify_response.status_code == 404:
                    self.log_result("On-Call - Verify Deletion", True, "Schedule successfully deleted (GET returns 404)")
                else:
                    self.log_result("On-Call - Verify Deletion", False, f"Schedule may not be deleted (GET returns {verify_response.status_code if verify_response else 'No response'})")
            else:
                self.log_result("On-Call - Delete Schedule", False, f"Delete response missing message: {delete_result}")
        else:
            self.log_result("On-Call - Delete Schedule", False, f"Failed to delete schedule: {response.status_code if response else 'No response'}")
    
    def test_bulk_ssm_installer(self):
        """Test Bulk SSM Installer endpoints"""
        print("\n=== Testing Bulk SSM Installer ===")
        
        # Test 1: GET /api/companies/comp-acme/instances-without-ssm (should scan EC2 instances)
        response = self.make_request('GET', '/companies/comp-acme/instances-without-ssm')
        if response and response.status_code == 200:
            instances_data = response.json()
            
            # Check response structure
            if 'instances_without_ssm' in instances_data and 'count' in instances_data:
                instances = instances_data.get('instances_without_ssm', [])
                count = instances_data.get('count', 0)
                company_name = instances_data.get('company_name')
                region = instances_data.get('region')
                
                self.log_result("SSM Installer - Scan Instances", True, f"Instance scan completed: {count} instances without SSM found for {company_name} in {region}")
            else:
                self.log_result("SSM Installer - Scan Instances", False, f"Instance scan response missing required fields: {instances_data}")
        elif response and response.status_code == 400:
            # This is expected if AWS credentials are not configured
            error_response = response.json()
            error_detail = error_response.get('detail', '')
            if 'AWS credentials not configured' in error_detail:
                self.log_result("SSM Installer - Scan Instances", True, f"Instance scan correctly requires AWS credentials: {error_detail}")
            else:
                self.log_result("SSM Installer - Scan Instances", False, f"Unexpected 400 error: {error_detail}")
        else:
            self.log_result("SSM Installer - Scan Instances", False, f"Failed to scan instances: {response.status_code if response else 'No response'}")
        
        # Test 2: POST /api/companies/comp-acme/ssm/bulk-install with instance IDs
        install_data = {
            "instance_ids": ["i-test123", "i-test456"]
        }
        
        response = self.make_request('POST', '/companies/comp-acme/ssm/bulk-install', json=install_data)
        if response and response.status_code == 200:
            install_result = response.json()
            
            # Check response structure
            if 'command_id' in install_result:
                command_id = install_result.get('command_id')
                status = install_result.get('status', 'unknown')
                
                self.log_result("SSM Installer - Bulk Install", True, f"SSM bulk install initiated: command_id={command_id}, status={status}")
                
                # Test 3: GET /api/companies/comp-acme/ssm/installation-status/{command_id} (check status)
                if command_id:
                    status_response = self.make_request('GET', f'/companies/comp-acme/ssm/installation-status/{command_id}')
                    if status_response and status_response.status_code == 200:
                        status_result = status_response.json()
                        
                        if 'command_id' in status_result:
                            cmd_status = status_result.get('status', 'unknown')
                            cmd_id = status_result.get('command_id')
                            
                            self.log_result("SSM Installer - Check Status", True, f"Installation status retrieved: command_id={cmd_id}, status={cmd_status}")
                        else:
                            self.log_result("SSM Installer - Check Status", False, f"Status response missing command_id: {status_result}")
                    else:
                        self.log_result("SSM Installer - Check Status", False, f"Failed to get installation status: {status_response.status_code if status_response else 'No response'}")
                else:
                    self.log_result("SSM Installer - Check Status", False, "No command_id available for status check")
            else:
                self.log_result("SSM Installer - Bulk Install", False, f"Bulk install response missing command_id: {install_result}")
        elif response and response.status_code == 400:
            # This is expected if AWS credentials are not configured or instances are invalid
            error_response = response.json()
            error_detail = error_response.get('detail', '')
            if 'AWS credentials not configured' in error_detail or 'not configured' in error_detail:
                self.log_result("SSM Installer - Bulk Install", True, f"Bulk install correctly validates AWS credentials: {error_detail}")
                
                # Still test the status endpoint with a dummy command ID
                dummy_command_id = "test-command-123"
                status_response = self.make_request('GET', f'/companies/comp-acme/ssm/installation-status/{dummy_command_id}')
                if status_response and status_response.status_code in [200, 404]:
                    self.log_result("SSM Installer - Check Status (Dummy)", True, f"Status endpoint accessible (returns {status_response.status_code})")
                else:
                    self.log_result("SSM Installer - Check Status (Dummy)", False, f"Status endpoint not accessible: {status_response.status_code if status_response else 'No response'}")
            else:
                self.log_result("SSM Installer - Bulk Install", False, f"Unexpected 400 error: {error_detail}")
        else:
            self.log_result("SSM Installer - Bulk Install", False, f"Failed to initiate bulk install: {response.status_code if response else 'No response'}")
    
    def run_msp_tests(self):
        """Run all MSP-focused improvement tests"""
        print("🚀 Starting MSP-Focused Improvements Backend API Tests")
        print(f"Backend URL: {self.base_url}")
        print("=" * 80)
        
        # Authenticate first
        if not self.authenticate():
            print("❌ Authentication failed - stopping tests")
            return self.print_summary()
        
        # Run MSP tests
        self.test_aws_credentials_management()
        self.test_on_call_scheduling()
        self.test_bulk_ssm_installer()
        
        # Print summary
        return self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "=" * 60)
        print("MSP TEST SUMMARY")
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
    tester = MSPTester()
    summary = tester.run_msp_tests()
    
    # Exit with error code if tests failed
    if summary['failed'] > 0:
        sys.exit(1)
    else:
        print("\n🎉 All MSP tests passed!")
        sys.exit(0)