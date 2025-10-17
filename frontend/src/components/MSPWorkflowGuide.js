import React, { useState } from 'react';
import { X, ChevronDown, ChevronUp, BookOpen, Zap, Shield, Mail, Server, CheckCircle, AlertCircle, Users, ArrowRight, Cloud, Key, Lock } from 'lucide-react';

/**
 * MSP Workflow Guide Component
 * Comprehensive in-app guide showing how Alert Whisperer works like real MSPs
 * Explains: Integration, Automation, Remote Execution, Notifications, Security
 */
const MSPWorkflowGuide = ({ onClose }) => {
  const [expandedSection, setExpandedSection] = useState('overview');

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-cyan-500/30 rounded-xl max-w-5xl w-full my-8 shadow-2xl">
        {/* Header */}
        <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border-b border-cyan-500/30 p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-cyan-500/20 rounded-lg">
                <BookOpen className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">Alert Whisperer MSP Platform</h2>
                <p className="text-cyan-400 text-sm">How Your System Automates Like Real MSPs</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/10 rounded-lg transition-colors"
            >
              <X className="w-6 h-6 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
          {/* Quick Stats */}
          <div className="grid grid-cols-4 gap-4 mb-6">
            <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-green-400">40-70%</div>
              <div className="text-xs text-slate-400 mt-1">Noise Reduced</div>
            </div>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-blue-400">20-30%</div>
              <div className="text-xs text-slate-400 mt-1">Auto-Fixed</div>
            </div>
            <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-orange-400">70%</div>
              <div className="text-xs text-slate-400 mt-1">To Technicians</div>
            </div>
            <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-purple-400">100%</div>
              <div className="text-xs text-slate-400 mt-1">Secure & Remote</div>
            </div>
          </div>

          {/* Overview Section */}
          <Section
            icon={Zap}
            title="How Alert Whisperer Works (Like Real MSPs)"
            expanded={expandedSection === 'overview'}
            onToggle={() => toggleSection('overview')}
          >
            <div className="space-y-4">
              <p className="text-slate-300 leading-relaxed">
                <strong className="text-cyan-400">Alert Whisperer</strong> automates IT service delivery for companies without IT teams - exactly like real Managed Service Providers (MSPs). We manage your clients' infrastructure remotely, filter noise, auto-fix common issues, and notify technicians only when human intervention is needed.
              </p>

              {/* Visual Workflow */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                <h4 className="text-white font-semibold mb-4 flex items-center gap-2">
                  <ArrowRight className="w-4 h-4 text-cyan-400" />
                  Complete MSP Automation Workflow
                </h4>
                <div className="space-y-3">
                  <WorkflowStep
                    number="1"
                    title="Alerts Arrive"
                    description="Client servers send alerts via webhook (CPU high, disk full, service down)"
                    color="blue"
                  />
                  <WorkflowStep
                    number="2"
                    title="AI Correlation & Noise Reduction"
                    description="System groups related alerts → Reduces 100 alerts to 15-30 incidents (40-70% noise reduced)"
                    color="purple"
                  />
                  <WorkflowStep
                    number="3"
                    title="Auto-Remediation (20-30%)"
                    description="Simple issues auto-fixed via AWS SSM: Restart services, clear disk space, fix permissions"
                    color="green"
                  />
                  <WorkflowStep
                    number="4"
                    title="Technician Assignment (70%)"
                    description="Remaining incidents auto-assigned to available technicians based on skills & workload"
                    color="orange"
                  />
                  <WorkflowStep
                    number="5"
                    title="Email Notifications"
                    description="Technicians receive detailed email with incident info and dashboard link"
                    color="red"
                  />
                  <WorkflowStep
                    number="6"
                    title="Remote Resolution"
                    description="Technicians resolve via dashboard - run scripts remotely using AWS SSM (no SSH/VPN needed)"
                    color="cyan"
                  />
                </div>
              </div>
            </div>
          </Section>

          {/* Integration Section */}
          <Section
            icon={Cloud}
            title="How Small Companies Integrate (No IT Team Needed)"
            expanded={expandedSection === 'integration'}
            onToggle={() => toggleSection('integration')}
          >
            <div className="space-y-4">
              <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4">
                <h4 className="text-cyan-400 font-semibold mb-2 flex items-center gap-2">
                  <Key className="w-4 h-4" />
                  What MSPs Share with Clients
                </h4>
                <ul className="space-y-2 text-slate-300 text-sm">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                    <span><strong>API Key:</strong> Unique key per company (aw_xxxxx) - like a password for their alerts</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                    <span><strong>Webhook URL:</strong> Where to send alerts (https://alertwhisperer.com/api/webhooks/alerts)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                    <span><strong>Integration Guide:</strong> Step-by-step docs for their monitoring tools (Datadog, Zabbix, CloudWatch)</span>
                  </li>
                </ul>
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                <h4 className="text-white font-semibold mb-3">AWS-First Architecture (Why AWS?)</h4>
                <p className="text-slate-300 text-sm leading-relaxed mb-3">
                  Most companies use <strong className="text-orange-400">AWS</strong> for cloud infrastructure. Alert Whisperer is AWS-native, supporting:
                </p>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="bg-orange-500/10 border border-orange-500/30 rounded p-3">
                    <div className="font-semibold text-orange-400 mb-1">AWS Systems Manager (SSM)</div>
                    <div className="text-slate-400">Remote script execution without SSH</div>
                  </div>
                  <div className="bg-orange-500/10 border border-orange-500/30 rounded p-3">
                    <div className="font-semibold text-orange-400 mb-1">AWS SES</div>
                    <div className="text-slate-400">Email notifications to technicians</div>
                  </div>
                  <div className="bg-orange-500/10 border border-orange-500/30 rounded p-3">
                    <div className="font-semibold text-orange-400 mb-1">AWS Secrets Manager</div>
                    <div className="text-slate-400">Secure credential storage</div>
                  </div>
                  <div className="bg-orange-500/10 border border-orange-500/30 rounded p-3">
                    <div className="font-semibold text-orange-400 mb-1">AWS Patch Manager</div>
                    <div className="text-slate-400">Automated patching & compliance</div>
                  </div>
                </div>
                <p className="text-slate-400 text-xs mt-3">
                  <em>Note: Azure and other cloud support is on the roadmap. AWS is our primary focus for maximum automation.</em>
                </p>
              </div>

              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                <h4 className="text-blue-400 font-semibold mb-2 flex items-center gap-2">
                  <Server className="w-4 h-4" />
                  Client Setup Requirements (One-Time)
                </h4>
                <ol className="space-y-2 text-slate-300 text-sm list-decimal list-inside">
                  <li><strong>Install SSM Agent</strong> on their AWS EC2 servers (Ubuntu, Amazon Linux, Windows)</li>
                  <li><strong>Attach IAM Role</strong> to instances (allows SSM access - no passwords needed)</li>
                  <li><strong>Configure Monitoring Tool</strong> to send alerts to MSP's webhook URL</li>
                  <li><strong>Test Connection</strong> via Alert Whisperer dashboard</li>
                </ol>
                <div className="mt-3 text-xs text-slate-400 italic">
                  💡 After setup, MSPs can run commands remotely on client servers WITHOUT SSH, VPN, or client passwords!
                </div>
              </div>
            </div>
          </Section>

          {/* Remote Execution Section */}
          <Section
            icon={Server}
            title="Remote Script Execution (No SSH/Passwords Required)"
            expanded={expandedSection === 'remote'}
            onToggle={() => toggleSection('remote')}
          >
            <div className="space-y-4">
              <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
                <h4 className="text-purple-400 font-semibold mb-2">How MSPs Access Client Infrastructure</h4>
                <p className="text-slate-300 text-sm leading-relaxed">
                  Unlike traditional MSPs that require VPN, SSH keys, or client passwords, Alert Whisperer uses <strong className="text-purple-400">AWS Systems Manager (SSM)</strong> - Amazon's secure remote management service.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                  <h5 className="text-red-400 font-semibold mb-2 text-sm flex items-center gap-2">
                    <X className="w-4 h-4" />
                    Traditional MSP (Old Way)
                  </h5>
                  <ul className="space-y-1 text-xs text-slate-400">
                    <li>❌ Requires VPN setup (complex)</li>
                    <li>❌ SSH keys or RDP passwords</li>
                    <li>❌ Firewall port openings (security risk)</li>
                    <li>❌ Client must manage credentials</li>
                    <li>❌ Hard to audit who did what</li>
                  </ul>
                </div>
                <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                  <h5 className="text-green-400 font-semibold mb-2 text-sm flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    Alert Whisperer (AWS SSM)
                  </h5>
                  <ul className="space-y-1 text-xs text-slate-300">
                    <li>✅ No VPN needed (AWS-native)</li>
                    <li>✅ No passwords or SSH keys</li>
                    <li>✅ No firewall changes required</li>
                    <li>✅ IAM roles control access automatically</li>
                    <li>✅ Full audit trail of every command</li>
                  </ul>
                </div>
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                <h4 className="text-white font-semibold mb-3 flex items-center gap-2">
                  <Zap className="w-4 h-4 text-yellow-400" />
                  What Technicians Can Do Remotely
                </h4>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-300">Restart services (nginx, apache, mysql)</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-300">Clear disk space (logs, temp files)</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-300">Fix file permissions</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-300">Check system health (CPU, memory, disk)</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-300">Apply security patches</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-300">Run custom diagnostic scripts</span>
                  </div>
                </div>
                <div className="mt-3 p-3 bg-cyan-500/10 border border-cyan-500/30 rounded text-xs text-cyan-400">
                  💡 All commands run via AWS SSM - no direct server access needed. Client infrastructure stays secure.
                </div>
              </div>
            </div>
          </Section>

          {/* Notification Section */}
          <Section
            icon={Mail}
            title="Email Notifications & Technician Assignment"
            expanded={expandedSection === 'notifications'}
            onToggle={() => toggleSection('notifications')}
          >
            <div className="space-y-4">
              <p className="text-slate-300 text-sm leading-relaxed">
                After correlation and auto-remediation, <strong className="text-orange-400">remaining incidents (70%)</strong> are automatically assigned to technicians based on their skills, current workload, and availability.
              </p>

              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                <h4 className="text-white font-semibold mb-3">What Happens When Incident is Assigned?</h4>
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <div className="bg-orange-500/20 rounded-full p-2 flex-shrink-0">
                      <Users className="w-4 h-4 text-orange-400" />
                    </div>
                    <div>
                      <div className="text-cyan-400 font-semibold text-sm">1. Auto-Assignment</div>
                      <div className="text-slate-400 text-xs">System selects best available technician (round-robin, skill-based, or least-busy strategy)</div>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <div className="bg-blue-500/20 rounded-full p-2 flex-shrink-0">
                      <Mail className="w-4 h-4 text-blue-400" />
                    </div>
                    <div>
                      <div className="text-cyan-400 font-semibold text-sm">2. Email Notification (AWS SES)</div>
                      <div className="text-slate-400 text-xs">Technician receives detailed email with incident details, priority score, affected assets, and dashboard link</div>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <div className="bg-green-500/20 rounded-full p-2 flex-shrink-0">
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    </div>
                    <div>
                      <div className="text-cyan-400 font-semibold text-sm">3. Dashboard Notification</div>
                      <div className="text-slate-400 text-xs">Real-time notification appears in Alert Whisperer dashboard (bell icon in header)</div>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <div className="bg-purple-500/20 rounded-full p-2 flex-shrink-0">
                      <Server className="w-4 h-4 text-purple-400" />
                    </div>
                    <div>
                      <div className="text-cyan-400 font-semibold text-sm">4. Technician Action</div>
                      <div className="text-slate-400 text-xs">Technician logs in, reviews incident, executes runbooks remotely via AWS SSM, updates status, adds notes</div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4">
                <h4 className="text-orange-400 font-semibold mb-2 text-sm">Overflow Queue (When All Technicians Busy)</h4>
                <p className="text-slate-300 text-xs leading-relaxed">
                  If all technicians are at capacity, incidents are added to an <strong>overflow queue</strong> and MSP admins are notified. This ensures no incident is lost even during alert storms.
                </p>
              </div>

              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                <h4 className="text-blue-400 font-semibold mb-2 text-sm">Escalation Workflow</h4>
                <p className="text-slate-300 text-xs leading-relaxed">
                  If an incident is not resolved within SLA time or marked as high-priority, it's automatically <strong>escalated</strong> to senior technicians or MSP admins with urgent email notifications.
                </p>
              </div>
            </div>
          </Section>

          {/* Security Section */}
          <Section
            icon={Shield}
            title="Security & Multi-Tenant Isolation"
            expanded={expandedSection === 'security'}
            onToggle={() => toggleSection('security')}
          >
            <div className="space-y-4">
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                <h4 className="text-green-400 font-semibold mb-3 flex items-center gap-2">
                  <Lock className="w-4 h-4" />
                  Production-Grade Security Features
                </h4>
                <div className="space-y-2 text-sm">
                  <SecurityFeature
                    title="HMAC-SHA256 Webhook Authentication"
                    description="GitHub-style cryptographic signatures prevent unauthorized alerts (like credit card security)"
                  />
                  <SecurityFeature
                    title="API Key Per Company"
                    description="Unique aw_xxxxx key per client - isolates data between companies"
                  />
                  <SecurityFeature
                    title="Replay Attack Protection"
                    description="5-minute timestamp validation window prevents old alerts from being reused"
                  />
                  <SecurityFeature
                    title="Rate Limiting"
                    description="Configurable limits (1-1000 req/min) prevent alert storms from overwhelming system"
                  />
                  <SecurityFeature
                    title="RBAC (Role-Based Access Control)"
                    description="3 roles: MSP Admin (full access), Company Admin (company-scoped), Technician (incident handling only)"
                  />
                  <SecurityFeature
                    title="Comprehensive Audit Logs"
                    description="Every action tracked: who executed what runbook, when, on which server (SOC 2 compliant)"
                  />
                  <SecurityFeature
                    title="Cross-Account IAM Roles"
                    description="AWS IAM roles with ExternalID - no long-lived credentials stored (AWS best practice)"
                  />
                  <SecurityFeature
                    title="Idempotency (Delivery Deduplication)"
                    description="24-hour duplicate detection prevents same alert from creating multiple incidents"
                  />
                </div>
              </div>

              <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4">
                <h4 className="text-cyan-400 font-semibold mb-2 text-sm">Multi-Tenant Data Isolation</h4>
                <p className="text-slate-300 text-xs leading-relaxed">
                  Each company's data is completely isolated. Technicians can only see incidents for companies they're assigned to. MSP admins have full visibility across all companies. Data is partitioned by company_id in MongoDB.
                </p>
              </div>
            </div>
          </Section>

          {/* Key Takeaways */}
          <div className="bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 rounded-lg p-6">
            <h3 className="text-white font-bold text-lg mb-4 flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-green-400" />
              Key Takeaways: Why This Works Like Real MSPs
            </h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-cyan-400 font-semibold mb-1">✅ No Client IT Team Needed</div>
                <div className="text-slate-300 text-xs">MSP handles everything remotely - perfect for small businesses</div>
              </div>
              <div>
                <div className="text-cyan-400 font-semibold mb-1">✅ 40-70% Noise Reduced</div>
                <div className="text-slate-300 text-xs">AI correlation groups 100 alerts → 15-30 actionable incidents</div>
              </div>
              <div>
                <div className="text-cyan-400 font-semibold mb-1">✅ 20-30% Auto-Fixed</div>
                <div className="text-slate-300 text-xs">Common issues resolved automatically (restart, cleanup, permissions)</div>
              </div>
              <div>
                <div className="text-cyan-400 font-semibold mb-1">✅ Zero SSH/VPN Required</div>
                <div className="text-slate-300 text-xs">AWS SSM enables secure remote execution without passwords</div>
              </div>
              <div>
                <div className="text-cyan-400 font-semibold mb-1">✅ Email Notifications</div>
                <div className="text-slate-300 text-xs">Technicians get detailed emails via AWS SES automatically</div>
              </div>
              <div>
                <div className="text-cyan-400 font-semibold mb-1">✅ Production-Grade Security</div>
                <div className="text-slate-300 text-xs">HMAC, RBAC, audit logs, rate limiting - enterprise-ready</div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-cyan-500/30 p-4 flex justify-between items-center bg-slate-800/50">
          <div className="text-sm text-slate-400">
            💡 <strong className="text-cyan-400">Need Help?</strong> Click the "❓ Help" button in the header for FAQs, workflows, and resources.
          </div>
          <button
            onClick={onClose}
            className="px-6 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition-colors font-semibold"
          >
            Got It!
          </button>
        </div>
      </div>
    </div>
  );
};

// Helper Components
const Section = ({ icon: Icon, title, children, expanded, onToggle }) => (
  <div className="bg-slate-800/30 border border-slate-700 rounded-lg overflow-hidden">
    <button
      onClick={onToggle}
      className="w-full flex items-center justify-between p-4 hover:bg-slate-800/50 transition-colors"
    >
      <div className="flex items-center gap-3">
        <div className="p-2 bg-cyan-500/20 rounded-lg">
          <Icon className="w-5 h-5 text-cyan-400" />
        </div>
        <span className="text-white font-semibold">{title}</span>
      </div>
      {expanded ? (
        <ChevronUp className="w-5 h-5 text-slate-400" />
      ) : (
        <ChevronDown className="w-5 h-5 text-slate-400" />
      )}
    </button>
    {expanded && (
      <div className="p-4 pt-0 border-t border-slate-700/50">
        {children}
      </div>
    )}
  </div>
);

const WorkflowStep = ({ number, title, description, color }) => {
  const colorClasses = {
    blue: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    purple: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    green: 'bg-green-500/20 text-green-400 border-green-500/30',
    orange: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    red: 'bg-red-500/20 text-red-400 border-red-500/30',
    cyan: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
  };

  return (
    <div className="flex items-start gap-3">
      <div className={`flex-shrink-0 w-8 h-8 rounded-full ${colorClasses[color]} border flex items-center justify-center font-bold text-sm`}>
        {number}
      </div>
      <div className="flex-1">
        <div className="text-white font-semibold text-sm">{title}</div>
        <div className="text-slate-400 text-xs mt-0.5">{description}</div>
      </div>
    </div>
  );
};

const SecurityFeature = ({ title, description }) => (
  <div className="flex items-start gap-2">
    <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
    <div>
      <div className="text-slate-200 font-semibold text-xs">{title}</div>
      <div className="text-slate-400 text-xs">{description}</div>
    </div>
  </div>
);

export default MSPWorkflowGuide;
