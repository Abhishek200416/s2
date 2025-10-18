import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Book, HelpCircle, FileText, Video, ArrowRight, CheckCircle,
  Server, Cloud, Terminal, Users, Settings, Activity, AlertCircle,
  Play, ExternalLink, Download, Building2, ArrowLeft
} from 'lucide-react';
import MSPIntegrationGuide from '../components/MSPIntegrationGuide';

const HelpCenter = () => {
  const navigate = useNavigate();
  const [expandedFaq, setExpandedFaq] = useState(null);

  const faqs = [
    {
      category: 'Getting Started',
      icon: Book,
      questions: [
        {
          q: 'What is Alert Whisperer?',
          a: 'Alert Whisperer is an MSP (Managed Service Provider) platform that helps you manage multiple client companies\' infrastructure. It receives alerts from monitoring tools, correlates them into incidents, and enables automated remediation through AWS SSM runbooks.'
        },
        {
          q: 'How do I onboard a new client company?',
          a: 'Go to the Companies tab → Click "Add Company" → Follow the onboarding wizard to: 1) Set up company details, 2) Install SSM agent on their servers, 3) Configure IAM roles, 4) Test connectivity. The wizard guides you through each step with copy-paste commands.'
        },
        {
          q: 'What is AWS SSM and why do I need it?',
          a: 'AWS Systems Manager (SSM) is a secure remote management service that lets you execute commands on EC2 instances without SSH/VPN. Alert Whisperer uses SSM to run automated runbooks (scripts) for incident remediation, like disk cleanup, service restarts, and security scans.'
        }
      ]
    },
    {
      category: 'Alert Management',
      icon: Activity,
      questions: [
        {
          q: 'How do I send alerts to Alert Whisperer?',
          a: 'Each company gets a unique API key and webhook URL. Configure your monitoring tools (Datadog, Zabbix, Prometheus, CloudWatch) to send webhook alerts to this URL. The system accepts JSON with fields: asset_name, signature, severity, message, tool_source.'
        },
        {
          q: 'What is alert correlation?',
          a: 'Alert correlation automatically groups similar alerts into incidents. For example, if 5 servers report "high CPU" within 15 minutes, they\'re correlated into one incident instead of 5 separate alerts. This reduces noise by 40-70%.'
        },
        {
          q: 'How does auto-assignment work?',
          a: 'When an incident is created, the system evaluates technician skills, workload, and availability to automatically assign the incident. You can configure rules like "Assign database incidents to technicians with \'database\' skill" or use round-robin distribution.'
        }
      ]
    },
    {
      category: 'SSM & Runbooks',
      icon: Terminal,
      questions: [
        {
          q: 'What are runbooks?',
          a: 'Runbooks are automated scripts that resolve common issues. Alert Whisperer includes 14 pre-built runbooks like disk cleanup, service restart, database health check, Docker container management, and security audits. You can execute them remotely via SSM on any connected server.'
        },
        {
          q: 'How do I check if SSM agent is working?',
          a: 'Go to Agent Health Dashboard to see real-time SSM agent status for all instances. Green = Online, Yellow = Connection Lost, Red = Inactive. You can test connectivity by clicking "Test" next to any instance.'
        },
        {
          q: 'Can I create custom runbooks?',
          a: 'Yes! Go to Runbook Library → Add Custom Runbook. Write your bash/PowerShell script, set risk level (low/medium/high), and it will be available for execution on any connected server.'
        }
      ]
    },
    {
      category: 'Security & Permissions',
      icon: Settings,
      questions: [
        {
          q: 'What are the user roles?',
          a: 'There are 3 roles: 1) MSP Admin - Full access to all companies and settings, 2) Company Admin - Manage their company\'s incidents and technicians, 3) Technician - View and resolve assigned incidents only.'
        },
        {
          q: 'How secure is webhook authentication?',
          a: 'Alert Whisperer uses API key + optional HMAC-SHA256 signature verification (GitHub-style). HMAC includes timestamp replay protection (5-min window) and constant-time comparison to prevent timing attacks. This ensures only authorized sources can send alerts.'
        },
        {
          q: 'Do you need SSH/VPN access to my servers?',
          a: 'No! Alert Whisperer uses AWS SSM for secure, agent-based remote access. There\'s no need for SSH keys, VPN tunnels, or firewall exceptions. All communication goes through AWS\' secure infrastructure.'
        }
      ]
    },
    {
      category: 'Troubleshooting',
      icon: AlertCircle,
      questions: [
        {
          q: 'My SSM agent shows "Offline" - how do I fix it?',
          a: 'Common fixes: 1) Verify SSM agent is running: systemctl status amazon-ssm-agent, 2) Check IAM role has AmazonSSMManagedInstanceCore policy, 3) Ensure instance has internet access or VPC endpoints, 4) Wait 2-3 minutes for agent registration after changes.'
        },
        {
          q: 'Alerts aren\'t being received - what should I check?',
          a: 'Verify: 1) API key is correct in monitoring tool config, 2) Webhook URL includes /api/webhooks/alerts, 3) Payload format matches: asset_name, signature, severity, message, tool_source, 4) Check rate limiting settings (default: 60/min).'
        },
        {
          q: 'How do I reset a technician\'s password?',
          a: 'As an MSP Admin, go to Technicians page → Click on technician → Edit → Change Password. The technician will need to use the new password on next login.'
        }
      ]
    }
  ];

  const workflows = [
    {
      title: 'Complete MSP Workflow',
      icon: Activity,
      steps: [
        'MSP onboards new client company in Alert Whisperer',
        'Client installs SSM agent on their servers (5-10 min)',
        'Client configures monitoring tools to send webhooks',
        'Alerts arrive → System correlates into incidents',
        'Auto-assignment routes incident to skilled technician',
        'Technician reviews incident → Executes runbook via SSM',
        'Issue resolved → Incident closed → KPIs updated'
      ]
    },
    {
      title: 'Alert to Resolution',
      icon: CheckCircle,
      steps: [
        'Monitoring tool detects issue (e.g., "Disk 90% full")',
        'Tool sends webhook to Alert Whisperer with alert details',
        'System receives alert → Stores in database → Broadcasts to dashboard',
        'Correlation engine groups similar alerts within 15-min window',
        'Incident created with priority score (severity + factors)',
        'Auto-assignment picks technician based on skills + workload',
        'Technician gets email notification → Views incident',
        'Technician executes "Clean Disk Space" runbook on affected server',
        'Runbook clears temp files → Disk usage drops to 60%',
        'Technician marks incident as resolved → MTTR tracked'
      ]
    },
    {
      title: 'Runbook Execution',
      icon: Terminal,
      steps: [
        'Technician opens incident from dashboard',
        'Clicks "Execute Runbook" → Selects runbook (e.g., Restart Service)',
        'Enters target instance IDs (e.g., i-abc123, i-def456)',
        'System checks approval requirements (low/medium/high risk)',
        'If approved, sends SSM Run Command to AWS',
        'AWS executes script on target instances via SSM agent',
        'Real-time logs streamed back to Alert Whisperer UI',
        'Execution completes → Status: Success/Failed shown',
        'Incident updated with remediation details'
      ]
    }
  ];

  const quickLinks = [
    {
      title: 'Video Tutorials',
      icon: Video,
      links: [
        { name: 'Getting Started with Alert Whisperer', url: '#' },
        { name: 'Onboarding Your First Client', url: '#' },
        { name: 'Setting Up SSM Agent', url: '#' },
        { name: 'Creating Custom Runbooks', url: '#' }
      ]
    },
    {
      title: 'Documentation',
      icon: FileText,
      links: [
        { name: 'AWS Integration Guide', url: '/aws-integration-guide' },
        { name: 'API Reference', url: '/api-docs' },
        { name: 'Webhook Security Guide', url: '/webhook-security' },
        { name: 'RBAC Permissions Matrix', url: '/rbac-guide' }
      ]
    },
    {
      title: 'Downloads',
      icon: Download,
      links: [
        { name: 'SSM Agent Installer (Ubuntu)', url: '#' },
        { name: 'SSM Agent Installer (Windows)', url: '#' },
        { name: 'IAM Policy Templates', url: '#' },
        { name: 'Monitoring Tool Configs', url: '#' }
      ]
    }
  ];

  return (
    <div className="min-h-screen bg-slate-950 py-8">
      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div className="mb-8">
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 text-cyan-400 hover:text-cyan-300 mb-4 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
            <span>Back</span>
          </button>
          <h1 className="text-4xl font-bold text-white mb-3">Help Center</h1>
          <p className="text-lg text-slate-300">
            Everything you need to know about Alert Whisperer
          </p>
        </div>

        <Tabs defaultValue="integration" className="space-y-6">
          <TabsList className="bg-slate-900/50 border border-slate-800">
            <TabsTrigger
              value="integration"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Building2 className="w-4 h-4 mr-2" />
              MSP Integration
            </TabsTrigger>
            <TabsTrigger
              value="faq"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <HelpCircle className="w-4 h-4 mr-2" />
              FAQs
            </TabsTrigger>
            <TabsTrigger
              value="workflows"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Activity className="w-4 h-4 mr-2" />
              Workflows
            </TabsTrigger>
          </TabsList>

          {/* MSP Integration Tab */}
          <TabsContent value="integration">
            <MSPIntegrationGuide />
          </TabsContent>

          {/* FAQs Tab */}
          <TabsContent value="faq">
            <div className="space-y-6">
              {faqs.map((category) => {
                const Icon = category.icon;
                return (
                  <Card key={category.category} className="bg-slate-900/50 border-slate-800">
                    <CardHeader>
                      <CardTitle className="text-white flex items-center">
                        <Icon className="w-5 h-5 mr-2 text-cyan-400" />
                        {category.category}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {category.questions.map((faq, index) => (
                        <div
                          key={index}
                          className="border border-slate-700 rounded-lg overflow-hidden"
                        >
                          <button
                            onClick={() =>
                              setExpandedFaq(
                                expandedFaq === `${category.category}-${index}`
                                  ? null
                                  : `${category.category}-${index}`
                              )
                            }
                            className="w-full p-4 text-left hover:bg-slate-800/50 transition-colors"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-white font-medium">{faq.q}</span>
                              <ArrowRight
                                className={`w-5 h-5 text-slate-400 transition-transform ${
                                  expandedFaq === `${category.category}-${index}`
                                    ? 'rotate-90'
                                    : ''
                                }`}
                              />
                            </div>
                          </button>
                          {expandedFaq === `${category.category}-${index}` && (
                            <div className="p-4 pt-0 text-slate-400 leading-relaxed">
                              {faq.a}
                            </div>
                          )}
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </TabsContent>

          {/* Workflows Tab */}
          <TabsContent value="workflows">
            <div className="space-y-6">
              {workflows.map((workflow) => {
                const Icon = workflow.icon;
                return (
                  <Card key={workflow.title} className="bg-slate-900/50 border-slate-800">
                    <CardHeader>
                      <CardTitle className="text-white flex items-center">
                        <Icon className="w-5 h-5 mr-2 text-cyan-400" />
                        {workflow.title}
                      </CardTitle>
                      <CardDescription className="text-slate-400">
                        Step-by-step process flow
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="relative">
                        {/* Vertical Line */}
                        <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-slate-700" />
                        
                        {/* Steps */}
                        <div className="space-y-6">
                          {workflow.steps.map((step, index) => (
                            <div key={index} className="flex items-start gap-4 relative">
                              {/* Step Number */}
                              <div className="relative z-10 flex-shrink-0 w-8 h-8 rounded-full bg-cyan-500 text-white flex items-center justify-center font-bold text-sm">
                                {index + 1}
                              </div>
                              
                              {/* Step Content */}
                              <div className="flex-1 pt-1">
                                <p className="text-slate-300 leading-relaxed">{step}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default HelpCenter;
