import React, { useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  CheckCircle, AlertCircle, ArrowRight, Server, 
  Zap, Users, Play, TrendingUp, Shield, Bell, FileText, ChevronDown
} from 'lucide-react';

/**
 * How It Works - Permanent visible guide showing exactly how the MSP system operates
 * This appears at the top of the dashboard explaining the automation flow
 */
const HowItWorksGuide = () => {
  const workflowRef = useRef(null);

  const scrollToWorkflow = () => {
    workflowRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const steps = [
    {
      id: 1,
      title: 'Client Sends Alert',
      description: 'Monitoring tools (Datadog, Zabbix, etc.) detect issues and send webhook alerts to Alert Whisperer',
      icon: Bell,
      color: 'blue',
      details: [
        'Webhook URL with unique API key',
        'HMAC-SHA256 security verification',
        'Rate limiting (prevents alert storms)',
        'Idempotency (duplicate detection)'
      ],
      automated: true
    },
    {
      id: 2,
      title: 'AI Correlation',
      description: 'System groups similar alerts into single incidents, reducing noise by 70%+',
      icon: Zap,
      color: 'purple',
      details: [
        'Groups alerts within 15-min window',
        'Uses asset + signature matching',
        'AI detects patterns (cascade, storm)',
        'Calculates priority score (0-100)'
      ],
      automated: true
    },
    {
      id: 3,
      title: 'Auto-Assignment',
      description: 'Intelligent routing assigns incidents to the best available technician',
      icon: Users,
      color: 'green',
      details: [
        'Skill-based matching',
        'Workload balancing',
        'Priority-based routing',
        'Overflow queue if all busy'
      ],
      automated: true
    },
    {
      id: 4,
      title: 'Remote Execution',
      description: 'Technician executes pre-built runbooks via AWS SSM - NO SSH/VPN needed!',
      icon: Play,
      color: 'cyan',
      details: [
        'AWS Systems Manager (SSM)',
        '20+ pre-built runbooks',
        'One-click execution',
        'Real-time output logs'
      ],
      automated: false
    },
    {
      id: 5,
      title: 'Auto-Escalation',
      description: 'Unhandled incidents automatically escalate to managers after 30 minutes',
      icon: AlertCircle,
      color: 'orange',
      details: [
        'Time-based triggers',
        'Email notifications',
        'Multi-level escalation',
        'SLA tracking'
      ],
      automated: true
    },
    {
      id: 6,
      title: 'Resolution & Metrics',
      description: 'System tracks resolution time, generates reports, and updates KPIs',
      icon: TrendingUp,
      color: 'teal',
      details: [
        'MTTR calculation',
        'Self-healing rate',
        'Noise reduction %',
        'Client reports'
      ],
      automated: true
    }
  ];

  return (
    <div className="bg-gradient-to-r from-slate-800 to-slate-900 border-2 border-cyan-500/30 rounded-xl p-6 mb-6">
      <div className="flex items-start justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2 flex items-center gap-2">
            <FileText className="w-6 h-6 text-cyan-400" />
            How Alert Whisperer Works
          </h2>
          <p className="text-slate-300">
            Complete automation from alert reception to resolution - just like real MSPs
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge className="bg-green-500/20 text-green-400 border-green-500/30 px-3 py-1">
            <CheckCircle className="w-4 h-4 mr-1" />
            Fully Automated
          </Badge>
          <Button 
            onClick={scrollToWorkflow}
            variant="outline"
            size="sm"
            className="border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
          >
            <ChevronDown className="w-4 h-4 mr-2" />
            View Process
          </Button>
        </div>
      </div>

      {/* Key Features */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-slate-900/50 border border-cyan-500/20 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <h4 className="text-white font-semibold">Remote Execution</h4>
          </div>
          <p className="text-slate-400 text-sm">
            Execute scripts on client servers via AWS SSM. <strong className="text-white">No SSH, no VPN, no RDP needed!</strong> 
            Works through AWS infrastructure.
          </p>
        </div>

        <div className="bg-slate-900/50 border border-green-500/20 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Users className="w-5 h-5 text-green-400" />
            <h4 className="text-white font-semibold">Overflow Handling</h4>
          </div>
          <p className="text-slate-400 text-sm">
            If all technicians are busy, new incidents go to a <strong className="text-white">queue</strong>. 
            Emails sent to managers. Next available tech gets assigned automatically.
          </p>
        </div>

        <div className="bg-slate-900/50 border border-purple-500/20 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-5 h-5 text-purple-400" />
            <h4 className="text-white font-semibold">Enterprise Security</h4>
          </div>
          <p className="text-slate-400 text-sm">
            HMAC authentication, API key rotation, rate limiting, RBAC, audit logs. 
            <strong className="text-white">Bank-level security</strong> for all integrations.
          </p>
        </div>
      </div>

      {/* FAQ Section */}
      <div className="bg-blue-900/10 border border-blue-500/20 rounded-lg p-4 mb-6">
        <h4 className="text-blue-300 font-semibold mb-3">❓ Common Questions</h4>
        <div className="space-y-2 text-sm">
          <div>
            <span className="text-white font-medium">Q: How do we run scripts remotely without SSH?</span>
            <p className="text-slate-400 ml-4">A: AWS Systems Manager (SSM) agent. Once installed on client servers, you can execute commands through AWS infrastructure.</p>
          </div>
          <div>
            <span className="text-white font-medium">Q: What if 30 alerts come in but only 15 technicians?</span>
            <p className="text-slate-400 ml-4">A: AI correlates 30 alerts → ~10 incidents (noise reduction). Auto-assigns to 10 techs. Remaining 5 go to queue. If tech finishes, next incident auto-assigned.</p>
          </div>
          <div>
            <span className="text-white font-medium">Q: Is this how real MSPs work?</span>
            <p className="text-slate-400 ml-4">A: Yes! Real MSPs use RMM tools (ConnectWise, Datto) + monitoring + ticketing. We combine all three with AI automation.</p>
          </div>
        </div>
      </div>

      {/* Flow Visualization - Now at the bottom */}
      <div ref={workflowRef} className="scroll-mt-6">
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <ArrowRight className="w-5 h-5 text-cyan-400" />
          Complete Workflow Process
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
          {steps.map((step, index) => {
            const Icon = step.icon;
            return (
              <React.Fragment key={step.id}>
                <Card className={`bg-slate-800 border-${step.color}-500/30 hover:border-${step.color}-500 transition-all relative`}>
                  <CardHeader>
                    <div className="flex items-start justify-between mb-2">
                      <div className={`w-10 h-10 rounded-lg bg-${step.color}-500/20 flex items-center justify-center`}>
                        <Icon className={`w-5 h-5 text-${step.color}-400`} />
                      </div>
                      <div className={`text-2xl font-bold text-${step.color}-400`}>
                        {step.id}
                      </div>
                    </div>
                    <CardTitle className="text-white text-sm">{step.title}</CardTitle>
                    <CardDescription className="text-xs">{step.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-1">
                      {step.details.map((detail, i) => (
                        <li key={i} className="text-xs text-slate-400 flex items-start gap-1">
                          <span className={`text-${step.color}-400 mt-0.5`}>•</span>
                          <span>{detail}</span>
                        </li>
                      ))}
                    </ul>
                    {step.automated && (
                      <Badge className="mt-2 text-xs bg-green-500/10 text-green-400">
                        <Zap className="w-3 h-3 mr-1" />
                        Auto
                      </Badge>
                    )}
                  </CardContent>
                  
                  {/* Arrow between steps */}
                  {index < steps.length - 1 && (
                    <div className="hidden md:block absolute -right-4 top-1/2 transform -translate-y-1/2 z-10">
                      <ArrowRight className="w-6 h-6 text-cyan-400" />
                    </div>
                  )}
                </Card>
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default HowItWorksGuide;
