import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { TrendingDown, CheckCircle, Clock, Info, ArrowRight, Calculator } from 'lucide-react';

const LiveKPIProof = ({ companyId }) => {
  const [impactData, setImpactData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (companyId) {
      loadImpactData();
      // Refresh every 30 seconds
      const interval = setInterval(loadImpactData, 30000);
      return () => clearInterval(interval);
    }
  }, [companyId]);

  const loadImpactData = async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_BACKEND_URL || ''}/api/metrics/before-after?company_id=${companyId}`,
        {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        }
      );
      if (response.ok) {
        const data = await response.json();
        setImpactData(data);
      }
    } catch (error) {
      console.error('Failed to load impact data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !impactData) {
    return null;
  }

  const { baseline, current, improvements, summary } = impactData;

  return (
    <div className="space-y-6">
      {/* Methodology Card */}
      <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-cyan-500/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-cyan-400">
            <Calculator className="w-5 h-5" />
            Live KPI Calculation Methodology
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-700">
            <h4 className="text-sm font-semibold text-slate-300 mb-2 flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              Real-Time Calculations (Not Estimates)
            </h4>
            <div className="space-y-2 text-sm text-slate-400">
              <div className="flex items-start gap-2">
                <span className="text-cyan-400 font-mono">•</span>
                <div>
                  <strong className="text-white">Noise Reduction:</strong> 
                  <code className="ml-2 px-2 py-0.5 bg-slate-800 rounded text-xs">
                    (1 - incidents/alerts) × 100
                  </code>
                  <p className="mt-1 text-xs">Calculated from actual MongoDB data: {current.incidents_count} incidents from {baseline.incidents_count} alerts</p>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-cyan-400 font-mono">•</span>
                <div>
                  <strong className="text-white">Self-Healed:</strong> 
                  <code className="ml-2 px-2 py-0.5 bg-slate-800 rounded text-xs">
                    (auto_resolved / total_incidents) × 100
                  </code>
                  <p className="mt-1 text-xs">Live count of incidents with auto-remediation flag</p>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-cyan-400 font-mono">•</span>
                <div>
                  <strong className="text-white">MTTR:</strong> 
                  <code className="ml-2 px-2 py-0.5 bg-slate-800 rounded text-xs">
                    average(resolved_at - created_at)
                  </code>
                  <p className="mt-1 text-xs">Mean time calculated from resolved incidents with timestamps</p>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Before/After Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Noise Reduction */}
        <Card className="bg-slate-900/50 border-emerald-500/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-emerald-400 text-base">
              <TrendingDown className="w-5 h-5" />
              Noise Reduction
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400 mb-1">Before Correlation</p>
                <p className="text-2xl font-bold text-slate-500">{baseline.noise_reduction_pct}%</p>
                <p className="text-xs text-slate-500 mt-1">{baseline.incidents_count} alerts</p>
              </div>
              <ArrowRight className="w-6 h-6 text-emerald-400" />
              <div>
                <p className="text-xs text-slate-400 mb-1">After Correlation</p>
                <p className="text-2xl font-bold text-emerald-400">{current.noise_reduction_pct.toFixed(1)}%</p>
                <p className="text-xs text-slate-400 mt-1">{current.incidents_count} incidents</p>
              </div>
            </div>
            
            <div className="bg-emerald-500/10 p-3 rounded-lg border border-emerald-500/20">
              <p className="text-sm font-semibold text-emerald-400 mb-1">
                +{improvements.noise_reduction.improvement.toFixed(1)}% Improvement
              </p>
              <p className="text-xs text-slate-400">
                Status: <span className="capitalize text-emerald-400">{improvements.noise_reduction.status}</span>
              </p>
              <p className="text-xs text-slate-500 mt-1">
                {summary.incidents_prevented} alerts prevented from becoming individual tickets
              </p>
            </div>
            
            <div className="text-xs text-slate-500 space-y-1">
              <p className="font-semibold text-slate-400">Live Data Source:</p>
              <p>✓ Alerts collection: {baseline.incidents_count} total</p>
              <p>✓ Incidents collection: {current.incidents_count} correlated</p>
              <p>✓ Calculation: (1 - {current.incidents_count}/{baseline.incidents_count}) × 100</p>
            </div>
          </CardContent>
        </Card>

        {/* Self-Healed */}
        <Card className="bg-slate-900/50 border-cyan-500/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-cyan-400 text-base">
              <CheckCircle className="w-5 h-5" />
              Self-Healed Incidents
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400 mb-1">Before Automation</p>
                <p className="text-2xl font-bold text-slate-500">{baseline.self_healed_pct}%</p>
                <p className="text-xs text-slate-500 mt-1">Manual only</p>
              </div>
              <ArrowRight className="w-6 h-6 text-cyan-400" />
              <div>
                <p className="text-xs text-slate-400 mb-1">With Automation</p>
                <p className="text-2xl font-bold text-cyan-400">{current.self_healed_pct.toFixed(1)}%</p>
                <p className="text-xs text-slate-400 mt-1">{current.self_healed_count} resolved</p>
              </div>
            </div>
            
            <div className="bg-cyan-500/10 p-3 rounded-lg border border-cyan-500/20">
              <p className="text-sm font-semibold text-cyan-400 mb-1">
                +{improvements.self_healed.improvement.toFixed(1)}% Improvement
              </p>
              <p className="text-xs text-slate-400">
                Status: <span className="capitalize text-cyan-400">{improvements.self_healed.status}</span>
              </p>
              <p className="text-xs text-slate-500 mt-1">
                {summary.auto_resolved_count} incidents resolved without human intervention
              </p>
            </div>
            
            <div className="text-xs text-slate-500 space-y-1">
              <p className="font-semibold text-slate-400">Live Data Source:</p>
              <p>✓ Query: incidents with auto_remediated=true</p>
              <p>✓ Count: {current.self_healed_count} auto-resolved</p>
              <p>✓ Percentage of total incidents resolved autonomously</p>
            </div>
          </CardContent>
        </Card>

        {/* MTTR */}
        <Card className="bg-slate-900/50 border-amber-500/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-amber-400 text-base">
              <Clock className="w-5 h-5" />
              Mean Time to Resolve
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400 mb-1">Before Alert Whisperer</p>
                <p className="text-2xl font-bold text-slate-500">{Math.round(baseline.mttr_minutes)}m</p>
                <p className="text-xs text-slate-500 mt-1">Manual resolution</p>
              </div>
              <ArrowRight className="w-6 h-6 text-amber-400" />
              <div>
                <p className="text-xs text-slate-400 mb-1">With Alert Whisperer</p>
                <p className="text-2xl font-bold text-amber-400">{Math.round(current.mttr_minutes)}m</p>
                <p className="text-xs text-slate-400 mt-1">Automated + Manual</p>
              </div>
            </div>
            
            <div className="bg-amber-500/10 p-3 rounded-lg border border-amber-500/20">
              <p className="text-sm font-semibold text-amber-400 mb-1">
                -{Math.abs(improvements.mttr.improvement).toFixed(1)} min Faster
              </p>
              <p className="text-xs text-slate-400">
                Status: <span className="capitalize text-amber-400">{improvements.mttr.status}</span>
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Average {summary.time_saved_per_incident} saved per incident
              </p>
            </div>
            
            <div className="text-xs text-slate-500 space-y-1">
              <p className="font-semibold text-slate-400">Live Data Source:</p>
              <p>✓ Calculated from resolved incidents</p>
              <p>✓ Formula: avg(resolved_at - created_at)</p>
              <p>✓ Includes both auto and manual resolutions</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Summary Banner */}
      <Card className="bg-gradient-to-r from-emerald-900/20 via-cyan-900/20 to-amber-900/20 border-cyan-500/30">
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-bold text-white mb-2">Live System Impact Summary</h3>
              <p className="text-sm text-slate-400">
                Real-time calculations based on actual production data • Updated every 30 seconds
              </p>
            </div>
            <button
              onClick={loadImpactData}
              className="px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 rounded-lg border border-cyan-500/30 transition-colors text-sm font-medium"
            >
              Refresh Now
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4">
            <div className="bg-slate-900/50 p-3 rounded-lg">
              <p className="text-xs text-slate-400 mb-1">Noise Reduced</p>
              <p className="text-xl font-bold text-emerald-400">{summary.noise_reduced}</p>
            </div>
            <div className="bg-slate-900/50 p-3 rounded-lg">
              <p className="text-xs text-slate-400 mb-1">Incidents Prevented</p>
              <p className="text-xl font-bold text-cyan-400">{summary.incidents_prevented}</p>
            </div>
            <div className="bg-slate-900/50 p-3 rounded-lg">
              <p className="text-xs text-slate-400 mb-1">Time Saved/Incident</p>
              <p className="text-xl font-bold text-amber-400">{summary.time_saved_per_incident}</p>
            </div>
            <div className="bg-slate-900/50 p-3 rounded-lg">
              <p className="text-xs text-slate-400 mb-1">Auto-Resolved</p>
              <p className="text-xl font-bold text-purple-400">{summary.auto_resolved_count}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Data Transparency Note */}
      <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="text-sm font-semibold text-blue-400 mb-1">Data Transparency & Proof</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              All metrics above are calculated in real-time from actual MongoDB data. The "Before" baseline represents 
              a system without correlation (1 alert = 1 incident). The "After" metrics show current performance with 
              Alert Whisperer's event correlation, automated remediation, and intelligent routing. These are not 
              estimates or targets – they are live measurements from your production data.
            </p>
            <p className="text-xs text-slate-500 mt-2">
              <strong>Verification:</strong> You can verify these calculations by querying the alerts and incidents 
              collections directly in MongoDB, or by using the <code className="px-1 py-0.5 bg-slate-800 rounded">/api/metrics/realtime</code> 
              and <code className="px-1 py-0.5 bg-slate-800 rounded">/api/metrics/before-after</code> API endpoints.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LiveKPIProof;
