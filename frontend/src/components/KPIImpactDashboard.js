import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { TrendingUp, TrendingDown, Activity, Target, CheckCircle, AlertTriangle, Shield } from 'lucide-react';

const KPIImpactDashboard = ({ companyId }) => {
  const [impactData, setImpactData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (companyId) {
      loadImpactData();
    }
  }, [companyId]);

  const loadImpactData = async () => {
    try {
      const response = await api.get(`/companies/${companyId}/kpis/impact`);
      setImpactData(response.data);
    } catch (error) {
      console.error('Failed to load KPI impact data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !impactData) {
    return <div className="text-slate-400">Loading impact analysis...</div>;
  }

  const { improvements, summary } = impactData;

  const getStatusColor = (status) => {
    switch (status) {
      case 'excellent': return 'text-green-400 bg-green-500/20 border-green-500/30';
      case 'good': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      case 'needs_improvement': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      default: return 'text-slate-400 bg-slate-500/20 border-slate-500/30';
    }
  };

  const ImprovementCard = ({ title, improvement, icon: Icon }) => {
    const isPositive = improvement.improvement > 0;
    const trend = isPositive ? TrendingUp : TrendingDown;
    
    return (
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-sm font-medium flex items-center gap-2">
            <Icon className="w-4 h-4 text-cyan-400" />
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Before/After Comparison */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <div className="text-xs text-slate-500 uppercase">Before</div>
              <div className="text-2xl font-bold text-slate-400">
                {typeof improvement.before === 'number' ? improvement.before.toFixed(1) : improvement.before}
                {title.includes('%') ? '%' : title.includes('MTTR') ? 'm' : ''}
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-xs text-slate-500 uppercase">After</div>
              <div className="text-2xl font-bold text-white">
                {typeof improvement.after === 'number' ? improvement.after.toFixed(1) : improvement.after}
                {title.includes('%') ? '%' : title.includes('MTTR') ? 'm' : ''}
              </div>
            </div>
          </div>

          {/* Improvement Indicator */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-700">
            <div className="flex items-center gap-2">
              {React.createElement(trend, { 
                className: `w-4 h-4 ${isPositive ? 'text-green-400' : 'text-red-400'}` 
              })}
              <span className={`text-sm font-semibold ${isPositive ? 'text-green-400' : 'text-red-400'}`}>
                {improvement.improvement > 0 ? '+' : ''}{improvement.improvement.toFixed(1)}
                {title.includes('%') || title.includes('Reduction') ? '%' : title.includes('MTTR') ? 'm' : ''}
              </span>
            </div>
            <Badge className={getStatusColor(improvement.status)}>
              {improvement.status === 'excellent' ? <CheckCircle className="w-3 h-3 mr-1" /> : <Target className="w-3 h-3 mr-1" />}
              {improvement.status.replace('_', ' ')}
            </Badge>
          </div>

          {/* Target */}
          <div className="text-xs text-slate-500">
            Target: {improvement.target}{title.includes('%') || title.includes('Reduction') ? '%' : title.includes('MTTR') ? '% reduction' : ''}
          </div>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="space-y-4">
      {/* Summary Banner */}
      <Card className="bg-gradient-to-r from-cyan-900/40 to-blue-900/40 border-cyan-500/30">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Alert Whisperer Impact Analysis
          </CardTitle>
          <CardDescription className="text-slate-300">
            Quantified improvements since implementing Alert Whisperer automation
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-2">
            <div className="text-center">
              <div className="text-3xl font-bold text-cyan-400">{summary.noise_reduced}</div>
              <div className="text-xs text-slate-400 mt-1">Noise Reduced</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-green-400">{summary.incidents_prevented}</div>
              <div className="text-xs text-slate-400 mt-1">Incidents Prevented</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-blue-400">{summary.time_saved_per_incident}</div>
              <div className="text-xs text-slate-400 mt-1">Time Saved/Incident</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-purple-400">{summary.auto_resolved_count}</div>
              <div className="text-xs text-slate-400 mt-1">Auto-Resolved</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detailed Improvements */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ImprovementCard 
          title="Noise Reduction %" 
          improvement={improvements.noise_reduction}
          icon={Activity}
        />
        <ImprovementCard 
          title="Self-Healed %" 
          improvement={improvements.self_healed}
          icon={CheckCircle}
        />
        <ImprovementCard 
          title="MTTR (Minutes)" 
          improvement={improvements.mttr}
          icon={TrendingDown}
        />
        <ImprovementCard 
          title="Patch Compliance %" 
          improvement={improvements.patch_compliance}
          icon={Shield}
        />
      </div>

      {/* Methodology Note */}
      <Card className="bg-slate-900/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white text-sm">Methodology</CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-slate-400 space-y-2">
          <p>
            <strong className="text-slate-300">Baseline (Before):</strong> Assumes manual operations without alert correlation, 
            automation, or patch management integration.
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Noise Reduction: 0% (every alert = separate incident)</li>
            <li>Self-Healed: 0% (no automation)</li>
            <li>MTTR: 2-3x longer due to manual investigation and remediation</li>
            <li>Patch Compliance: Typically 10-15% lower without automated tracking</li>
          </ul>
          <p className="pt-2">
            <strong className="text-slate-300">After Alert Whisperer:</strong> Real-time metrics from your current operations 
            showing measurable improvements in operational efficiency.
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

export default KPIImpactDashboard;
