import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { CheckCircle, AlertCircle, TrendingUp, BarChart3, Target } from 'lucide-react';

const IncidentAnalysis = ({ companyId, refreshTrigger }) => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (companyId) {
      loadStats();
    }
  }, [companyId, refreshTrigger]);

  const loadStats = async () => {
    try {
      const response = await api.get(`/incidents/stats?company_id=${companyId}`);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to load incident stats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-slate-400">Loading analysis...</div>;
  }

  if (!stats) {
    return <div className="text-slate-400">No data available</div>;
  }

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <Card className="bg-gradient-to-r from-cyan-900/40 to-blue-900/40 border-cyan-500/30">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <BarChart3 className="w-6 h-6 text-cyan-400" />
            Incident Decision Analysis
          </CardTitle>
          <CardDescription className="text-slate-300">
            Real-time analysis of incident decision status and automation effectiveness
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <div className="text-4xl font-bold text-white">{stats.total}</div>
              <div className="text-xs text-slate-400 mt-2">Total Incidents</div>
            </div>
            <div className="text-center p-4 bg-green-500/10 rounded-lg border border-green-500/30">
              <div className="text-4xl font-bold text-green-400">{stats.decided}</div>
              <div className="text-xs text-green-300 mt-2">Decided</div>
            </div>
            <div className="text-center p-4 bg-amber-500/10 rounded-lg border border-amber-500/30">
              <div className="text-4xl font-bold text-amber-400">{stats.not_decided}</div>
              <div className="text-xs text-amber-300 mt-2">Not Decided</div>
            </div>
            <div className="text-center p-4 bg-cyan-500/10 rounded-lg border border-cyan-500/30">
              <div className="text-4xl font-bold text-cyan-400">{stats.decided_percentage}%</div>
              <div className="text-xs text-cyan-300 mt-2">Decision Rate</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Decision Progress */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Target className="w-5 h-5 text-cyan-400" />
            Decision Progress
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-300">Incidents with Decisions</span>
              <span className="text-cyan-400 font-semibold">
                {stats.decided} / {stats.total} ({stats.decided_percentage}%)
              </span>
            </div>
            <Progress value={stats.decided_percentage} className="h-3" />
          </div>
          
          <div className="grid grid-cols-2 gap-3 mt-4">
            <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-sm text-slate-300">Decided</span>
              </div>
              <div className="text-2xl font-bold text-green-400">{stats.decided}</div>
              <p className="text-xs text-slate-400 mt-1">
                Automated decisions generated
              </p>
            </div>
            
            <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <AlertCircle className="w-4 h-4 text-amber-400" />
                <span className="text-sm text-slate-300">Pending</span>
              </div>
              <div className="text-2xl font-bold text-amber-400">{stats.not_decided}</div>
              <p className="text-xs text-slate-400 mt-1">
                Awaiting decision generation
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Status Breakdown */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-cyan-400" />
            Incident Status Breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-blue-500/10 rounded-lg border border-blue-500/30">
              <Badge className="bg-blue-500/20 text-blue-300 border-blue-500/30 mb-2">
                New
              </Badge>
              <div className="text-3xl font-bold text-blue-400">{stats.by_status.new}</div>
              <p className="text-xs text-slate-400 mt-1">Just created</p>
            </div>
            
            <div className="p-4 bg-amber-500/10 rounded-lg border border-amber-500/30">
              <Badge className="bg-amber-500/20 text-amber-300 border-amber-500/30 mb-2">
                In Progress
              </Badge>
              <div className="text-3xl font-bold text-amber-400">{stats.by_status.in_progress}</div>
              <p className="text-xs text-slate-400 mt-1">Being worked on</p>
            </div>
            
            <div className="p-4 bg-emerald-500/10 rounded-lg border border-emerald-500/30">
              <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/30 mb-2">
                Resolved
              </Badge>
              <div className="text-3xl font-bold text-emerald-400">{stats.by_status.resolved}</div>
              <p className="text-xs text-slate-400 mt-1">Successfully fixed</p>
            </div>
            
            <div className="p-4 bg-purple-500/10 rounded-lg border border-purple-500/30">
              <Badge className="bg-purple-500/20 text-purple-300 border-purple-500/30 mb-2">
                Escalated
              </Badge>
              <div className="text-3xl font-bold text-purple-400">{stats.by_status.escalated}</div>
              <p className="text-xs text-slate-400 mt-1">Needs attention</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Insights */}
      <Card className="bg-slate-900/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white text-sm">Analysis Insights</CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-slate-400 space-y-2">
          <p>
            <strong className="text-slate-300">Decision Rate:</strong> {stats.decided_percentage}% of incidents have automated decisions generated. 
            {stats.decided_percentage >= 80 ? ' Excellent automation coverage!' : stats.decided_percentage >= 50 ? ' Good automation rate.' : ' Consider enabling auto-correlation for better coverage.'}
          </p>
          <p>
            <strong className="text-slate-300">Resolution Rate:</strong> {stats.total > 0 ? Math.round((stats.by_status.resolved / stats.total) * 100) : 0}% of incidents have been resolved.
            {stats.by_status.resolved > stats.by_status.in_progress && ' Great resolution efficiency!'}
          </p>
          <p>
            <strong className="text-slate-300">Active Work:</strong> {stats.by_status.in_progress + stats.by_status.new} incidents currently need attention 
            ({stats.by_status.new} new, {stats.by_status.in_progress} in progress).
          </p>
          {stats.by_status.escalated > 0 && (
            <p className="text-amber-300">
              <strong>⚠️ Escalated:</strong> {stats.by_status.escalated} incident{stats.by_status.escalated > 1 ? 's' : ''} escalated and require immediate attention.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default IncidentAnalysis;
