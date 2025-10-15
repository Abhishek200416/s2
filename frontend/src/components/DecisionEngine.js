import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Brain, Zap } from 'lucide-react';

const DecisionEngine = ({ companyId }) => {
  return (
    <Card className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-purple-500/30" data-testid="decision-engine">
      <CardHeader>
        <CardTitle className="text-white flex items-center gap-2">
          <Brain className="w-5 h-5 text-purple-400" />
          Decision Engine
        </CardTitle>
        <CardDescription className="text-slate-300">
          Automated incident analysis and remediation decisions
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Engine Info */}
          <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
            <h4 className="text-sm font-medium text-white mb-3">Decision Criteria</h4>
            <ul className="space-y-2 text-sm text-slate-400">
              <li className="flex items-start gap-2">
                <Zap className="w-4 h-4 mt-0.5 text-cyan-400 flex-shrink-0" />
                <span>Correlates duplicate alerts by signature + asset</span>
              </li>
              <li className="flex items-start gap-2">
                <Zap className="w-4 h-4 mt-0.5 text-cyan-400 flex-shrink-0" />
                <span>Calculates priority score based on severity and alert count</span>
              </li>
              <li className="flex items-start gap-2">
                <Zap className="w-4 h-4 mt-0.5 text-cyan-400 flex-shrink-0" />
                <span>Auto-executes low-risk runbooks with approval</span>
              </li>
              <li className="flex items-start gap-2">
                <Zap className="w-4 h-4 mt-0.5 text-cyan-400 flex-shrink-0" />
                <span>Requests approval for medium/high-risk actions</span>
              </li>
              <li className="flex items-start gap-2">
                <Zap className="w-4 h-4 mt-0.5 text-cyan-400 flex-shrink-0" />
                <span>Escalates when no runbook available or approval denied</span>
              </li>
            </ul>
          </div>

          {/* Sample Decision JSON */}
          <div className="p-4 bg-slate-950/50 rounded-lg border border-slate-800">
            <h4 className="text-sm font-medium text-white mb-3">Sample Decision Output</h4>
            <div className="bg-slate-950 rounded p-3 font-mono text-xs overflow-x-auto">
              <pre className="text-slate-400">{`{
  "action": "EXECUTE",
  "reason": "Low-risk runbook auto-approved",
  "incident_id": "...",
  "priority_score": 42.5,
  "runbook_id": "restart_nginx",
  "approval_required": false,
  "health_check": {
    "type": "http",
    "status": 200
  },
  "escalation": {
    "skill_tag": "linux",
    "urgency": "medium"
  }
}`}</pre>
            </div>
          </div>

          {/* Action Flow */}
          <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700">
            <h4 className="text-sm font-medium text-white mb-3">Action Flow</h4>
            <div className="flex items-center gap-2 text-xs">
              <span className="px-2 py-1 bg-cyan-500/20 text-cyan-300 rounded border border-cyan-500/30">Event Correlation</span>
              <span className="text-slate-600">→</span>
              <span className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded border border-purple-500/30">Decision Engine</span>
              <span className="text-slate-600">→</span>
              <span className="px-2 py-1 bg-amber-500/20 text-amber-300 rounded border border-amber-500/30">Approval Check</span>
              <span className="text-slate-600">→</span>
              <span className="px-2 py-1 bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30">Execute</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default DecisionEngine;