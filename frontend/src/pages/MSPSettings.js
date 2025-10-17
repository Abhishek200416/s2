import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_BACKEND_URL || '';

function MSPSettings() {
  const [activeTab, setActiveTab] = useState('auto-assignment');
  const [companies, setCompanies] = useState([]);
  const [selectedCompany, setSelectedCompany] = useState('');
  const [loading, setLoading] = useState(false);

  // Auto-Assignment State
  const [assignmentRules, setAssignmentRules] = useState([]);
  const [techniciansList, setTechniciansList] = useState([]);
  
  // Escalation State
  const [escalationPolicies, setEscalationPolicies] = useState([]);
  
  // SLA State
  const [slaPolicies, setSlaPolicies] = useState([]);
  
  // Email Notifications State
  const [emailSettings, setEmailSettings] = useState(null);
  const [testEmailRecipient, setTestEmailRecipient] = useState('');
  const [testEmailResult, setTestEmailResult] = useState(null);

  useEffect(() => {
    fetchCompanies();
    fetchTechnicians();
  }, []);

  useEffect(() => {
    if (selectedCompany) {
      fetchCompanyData();
    }
  }, [selectedCompany]);

  const fetchCompanies = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_URL}/companies`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setCompanies(response.data);
      if (response.data.length > 0) {
        setSelectedCompany(response.data[0].id);
      }
    } catch (error) {
      console.error('Error fetching companies:', error);
    }
  };

  const fetchTechnicians = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_URL}/users`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setTechniciansList(response.data.filter(u => u.role === 'technician' || u.role === 'company_admin'));
    } catch (error) {
      console.error('Error fetching technicians:', error);
    }
  };

  const fetchCompanyData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      
      // Fetch auto-assignment rules
      const rulesRes = await axios.get(`${API_URL}/msp/auto-assignment/rules/${selectedCompany}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAssignmentRules(rulesRes.data);
      
      // Fetch escalation policies
      const escalationRes = await axios.get(`${API_URL}/msp/escalation/policies/${selectedCompany}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setEscalationPolicies(escalationRes.data);
      
      // Fetch SLA policies
      const slaRes = await axios.get(`${API_URL}/msp/sla/policies/${selectedCompany}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSlaPolicies(slaRes.data);
      
      // Fetch email notification settings
      const emailRes = await axios.get(`${API_URL}/msp/notifications/settings/${selectedCompany}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setEmailSettings(emailRes.data);
      
    } catch (error) {
      console.error('Error fetching company data:', error);
    } finally {
      setLoading(false);
    }
  };

  const sendTestEmail = async () => {
    if (!testEmailRecipient) {
      alert('Please enter email address');
      return;
    }
    
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(
        `${API_URL}/msp/notifications/test-email?recipient_email=${testEmailRecipient}`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      setTestEmailResult({ success: true, message: 'Test email sent successfully!' });
      setTimeout(() => setTestEmailResult(null), 5000);
    } catch (error) {
      setTestEmailResult({ success: false, message: error.response?.data?.detail || 'Failed to send test email' });
    }
  };

  const createAssignmentRule = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `${API_URL}/msp/auto-assignment/rules`,
        {
          company_id: selectedCompany,
          enabled: true,
          conditions: {},
          assignment_strategy: 'load_balance',
          required_skills: [],
          target_technicians: [],
          escalation_time_minutes: 30
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      fetchCompanyData();
    } catch (error) {
      console.error('Error creating rule:', error);
    }
  };

  const createEscalationPolicy = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `${API_URL}/msp/escalation/policies`,
        {
          company_id: selectedCompany,
          name: 'New Escalation Policy',
          enabled: true,
          trigger_conditions: {
            unacknowledged_minutes: 30,
            priority_min: 80
          },
          escalation_levels: [
            {
              level: 1,
              delay_minutes: 30,
              notify_roles: ['technician'],
              notify_users: []
            }
          ],
          sla_breach_action: 'escalate'
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      fetchCompanyData();
    } catch (error) {
      console.error('Error creating escalation policy:', error);
    }
  };

  const createSLAPolicy = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `${API_URL}/msp/sla/policies`,
        {
          company_id: selectedCompany,
          name: 'New SLA Policy',
          enabled: true,
          priority_slas: {
            critical: 60,
            high: 240,
            medium: 480,
            low: 1440
          },
          acknowledgment_sla_minutes: 15,
          breach_notification_enabled: true,
          breach_notification_recipients: []
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      fetchCompanyData();
    } catch (error) {
      console.error('Error creating SLA policy:', error);
    }
  };

  const tabs = [
    { id: 'auto-assignment', label: '🎯 Auto-Assignment', icon: '🎯' },
    { id: 'escalation', label: '🔥 Escalation', icon: '🔥' },
    { id: 'sla', label: '⏱️ SLA Policies', icon: '⏱️' },
    { id: 'email', label: '📧 Email Notifications', icon: '📧' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">⚙️ MSP Settings</h1>
            <p className="text-slate-400">Configure automation, escalation, and notification settings</p>
          </div>
          <button
            onClick={() => window.location.href = '/dashboard'}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
          >
            ← Back to Dashboard
          </button>
        </div>
      </div>

      {/* Company Selector */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
        <label className="block text-sm font-medium text-slate-300 mb-2">Select Company</label>
        <select
          value={selectedCompany}
          onChange={(e) => setSelectedCompany(e.target.value)}
          className="w-full max-w-md px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="">Select a company</option>
          {companies.map(company => (
            <option key={company.id} value={company.id}>{company.name}</option>
          ))}
        </select>
      </div>

      {selectedCompany && (
        <>
          {/* Tabs */}
          <div className="flex space-x-2 mb-6 overflow-x-auto">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-6 py-3 rounded-lg font-semibold transition-all whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            {loading ? (
              <div className="text-center py-12 text-slate-400">Loading settings...</div>
            ) : (
              <>
                {/* Auto-Assignment Tab */}
                {activeTab === 'auto-assignment' && (
                  <div>
                    <div className="flex items-center justify-between mb-6">
                      <h2 className="text-2xl font-bold text-white">Auto-Assignment Rules</h2>
                      <button
                        onClick={createAssignmentRule}
                        className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
                      >
                        + Add Rule
                      </button>
                    </div>

                    {assignmentRules.length === 0 ? (
                      <div className="text-center py-12">
                        <p className="text-slate-400 mb-4">No auto-assignment rules configured</p>
                        <button
                          onClick={createAssignmentRule}
                          className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
                        >
                          Create Default Rule
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {assignmentRules.map(rule => (
                          <div key={rule.id} className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                            <div className="flex items-center justify-between mb-4">
                              <div className="flex items-center space-x-3">
                                <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                                  rule.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                                }`}>
                                  {rule.enabled ? 'Enabled' : 'Disabled'}
                                </span>
                                <span className="text-white font-semibold">Priority: {rule.priority}</span>
                              </div>
                            </div>
                            <div className="grid grid-cols-2 gap-4 text-sm">
                              <div>
                                <span className="text-slate-400">Strategy:</span>
                                <span className="text-white ml-2">{rule.assignment_strategy}</span>
                              </div>
                              <div>
                                <span className="text-slate-400">Escalation Time:</span>
                                <span className="text-white ml-2">{rule.escalation_time_minutes} minutes</span>
                              </div>
                              {rule.required_skills.length > 0 && (
                                <div className="col-span-2">
                                  <span className="text-slate-400">Required Skills:</span>
                                  <div className="flex flex-wrap gap-2 mt-2">
                                    {rule.required_skills.map(skill => (
                                      <span key={skill} className="px-2 py-1 bg-blue-900 text-blue-300 rounded text-xs">
                                        {skill}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Info Box */}
                    <div className="mt-6 bg-blue-900 border border-blue-700 rounded-lg p-4">
                      <h3 className="text-blue-300 font-semibold mb-2">📖 Assignment Strategies</h3>
                      <ul className="text-blue-200 text-sm space-y-1">
                        <li><strong>Round Robin:</strong> Distributes incidents evenly among technicians</li>
                        <li><strong>Least Loaded:</strong> Assigns to technician with lowest workload</li>
                        <li><strong>Skill Match:</strong> Matches technician skills with incident requirements</li>
                        <li><strong>Load Balance:</strong> Balances skill match and workload</li>
                      </ul>
                    </div>
                  </div>
                )}

                {/* Escalation Tab */}
                {activeTab === 'escalation' && (
                  <div>
                    <div className="flex items-center justify-between mb-6">
                      <h2 className="text-2xl font-bold text-white">Escalation Policies</h2>
                      <button
                        onClick={createEscalationPolicy}
                        className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors"
                      >
                        + Add Policy
                      </button>
                    </div>

                    {escalationPolicies.length === 0 ? (
                      <div className="text-center py-12">
                        <p className="text-slate-400 mb-4">No escalation policies configured</p>
                        <button
                          onClick={createEscalationPolicy}
                          className="px-6 py-3 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors"
                        >
                          Create Default Policy
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {escalationPolicies.map(policy => (
                          <div key={policy.id} className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                            <div className="flex items-center justify-between mb-4">
                              <h3 className="text-xl font-semibold text-white">{policy.name}</h3>
                              <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                                policy.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                              }`}>
                                {policy.enabled ? 'Enabled' : 'Disabled'}
                              </span>
                            </div>
                            <div className="mb-4">
                              <h4 className="text-slate-300 font-medium mb-2">Trigger Conditions:</h4>
                              <div className="text-sm text-slate-400">
                                Unacknowledged for {policy.trigger_conditions.unacknowledged_minutes} minutes
                                or Priority ≥ {policy.trigger_conditions.priority_min}
                              </div>
                            </div>
                            <div>
                              <h4 className="text-slate-300 font-medium mb-2">Escalation Levels:</h4>
                              <div className="space-y-2">
                                {policy.escalation_levels.map(level => (
                                  <div key={level.level} className="bg-slate-800 rounded p-3 text-sm">
                                    <span className="text-white font-medium">Level {level.level}:</span>
                                    <span className="text-slate-400 ml-2">
                                      After {level.delay_minutes} min → Notify {level.notify_roles.join(', ')}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* SLA Tab */}
                {activeTab === 'sla' && (
                  <div>
                    <div className="flex items-center justify-between mb-6">
                      <h2 className="text-2xl font-bold text-white">SLA Policies</h2>
                      <button
                        onClick={createSLAPolicy}
                        className="px-4 py-2 bg-yellow-600 hover:bg-yellow-500 text-white rounded-lg transition-colors"
                      >
                        + Add Policy
                      </button>
                    </div>

                    {slaPolicies.length === 0 ? (
                      <div className="text-center py-12">
                        <p className="text-slate-400 mb-4">No SLA policies configured</p>
                        <button
                          onClick={createSLAPolicy}
                          className="px-6 py-3 bg-yellow-600 hover:bg-yellow-500 text-white rounded-lg transition-colors"
                        >
                          Create Default Policy
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {slaPolicies.map(policy => (
                          <div key={policy.id} className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                            <div className="flex items-center justify-between mb-4">
                              <h3 className="text-xl font-semibold text-white">{policy.name}</h3>
                              <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                                policy.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                              }`}>
                                {policy.enabled ? 'Enabled' : 'Disabled'}
                              </span>
                            </div>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                              <div className="bg-red-900 border border-red-700 rounded p-3 text-center">
                                <div className="text-red-300 text-sm mb-1">Critical</div>
                                <div className="text-white text-2xl font-bold">{policy.priority_slas.critical}</div>
                                <div className="text-red-300 text-xs">minutes</div>
                              </div>
                              <div className="bg-orange-900 border border-orange-700 rounded p-3 text-center">
                                <div className="text-orange-300 text-sm mb-1">High</div>
                                <div className="text-white text-2xl font-bold">{policy.priority_slas.high}</div>
                                <div className="text-orange-300 text-xs">minutes</div>
                              </div>
                              <div className="bg-yellow-900 border border-yellow-700 rounded p-3 text-center">
                                <div className="text-yellow-300 text-sm mb-1">Medium</div>
                                <div className="text-white text-2xl font-bold">{policy.priority_slas.medium}</div>
                                <div className="text-yellow-300 text-xs">minutes</div>
                              </div>
                              <div className="bg-blue-900 border border-blue-700 rounded p-3 text-center">
                                <div className="text-blue-300 text-sm mb-1">Low</div>
                                <div className="text-white text-2xl font-bold">{policy.priority_slas.low}</div>
                                <div className="text-blue-300 text-xs">minutes</div>
                              </div>
                            </div>
                            <div className="text-sm text-slate-400">
                              Acknowledgment SLA: {policy.acknowledgment_sla_minutes} minutes
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Email Notifications Tab */}
                {activeTab === 'email' && emailSettings && (
                  <div>
                    <h2 className="text-2xl font-bold text-white mb-6">Email Notification Settings</h2>
                    
                    {/* Email Status */}
                    <div className="bg-slate-900 border border-slate-700 rounded-lg p-6 mb-6">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold text-white">Email Service Status</h3>
                        <span className="px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
                          AWS SES Active
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            checked={emailSettings.notify_on_assignment}
                            readOnly
                            className="w-4 h-4"
                          />
                          <span className="text-slate-300">Assignment Notifications</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            checked={emailSettings.notify_on_escalation}
                            readOnly
                            className="w-4 h-4"
                          />
                          <span className="text-slate-300">Escalation Notifications</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            checked={emailSettings.notify_on_sla_breach}
                            readOnly
                            className="w-4 h-4"
                          />
                          <span className="text-slate-300">SLA Breach Notifications</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            checked={emailSettings.notify_on_resolution}
                            readOnly
                            className="w-4 h-4"
                          />
                          <span className="text-slate-300">Resolution Notifications</span>
                        </div>
                      </div>
                    </div>

                    {/* Test Email */}
                    <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                      <h3 className="text-lg font-semibold text-white mb-4">Send Test Email</h3>
                      <p className="text-slate-400 text-sm mb-4">
                        Verify your email service is working correctly by sending a test email
                      </p>
                      <div className="flex space-x-4">
                        <input
                          type="email"
                          placeholder="technician@company.com"
                          value={testEmailRecipient}
                          onChange={(e) => setTestEmailRecipient(e.target.value)}
                          className="flex-1 px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500"
                        />
                        <button
                          onClick={sendTestEmail}
                          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
                        >
                          📧 Send Test Email
                        </button>
                      </div>
                      {testEmailResult && (
                        <div className={`mt-4 p-4 rounded-lg ${
                          testEmailResult.success 
                            ? 'bg-green-900 border border-green-700 text-green-300' 
                            : 'bg-red-900 border border-red-700 text-red-300'
                        }`}>
                          {testEmailResult.message}
                        </div>
                      )}
                    </div>

                    {/* Email Templates Info */}
                    <div className="mt-6 bg-blue-900 border border-blue-700 rounded-lg p-4">
                      <h3 className="text-blue-300 font-semibold mb-2">📧 Email Templates</h3>
                      <ul className="text-blue-200 text-sm space-y-1">
                        <li><strong>Incident Assignment:</strong> Beautiful HTML email with incident details, priority, and dashboard link</li>
                        <li><strong>Escalation Alert:</strong> Urgent notification with escalation reason and immediate action required</li>
                        <li><strong>SLA Breach:</strong> Warning notification when SLA targets are about to be or have been breached</li>
                      </ul>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default MSPSettings;
