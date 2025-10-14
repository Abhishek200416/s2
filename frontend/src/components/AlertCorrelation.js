import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Zap, Play, TrendingDown, CheckCircle, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';

const AlertCorrelation = ({ companyId, companyName }) => {
  const [alerts, setAlerts] = useState([]);
  const [correlating, setCorrelating] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [correlationResult, setCorrelationResult] = useState(null);

  useEffect(() => {
    if (companyId) {
      loadAlerts();
    }
  }, [companyId]);

  const loadAlerts = async () => {
    try {
      const response = await api.get(`/alerts?company_id=${companyId}&status=active`);
      setAlerts(response.data);
    } catch (error) {
      console.error('Failed to load alerts:', error);
      toast.error('Failed to load alerts');
    }
  };

  const generateAlerts = async () => {
    setGenerating(true);
    try {
      await api.post(`/alerts/generate?company_id=${companyId}&count=50`);
      toast.success('Generated 50 sample alerts');
      await loadAlerts();
    } catch (error) {
      console.error('Failed to generate alerts:', error);
      toast.error('Failed to generate alerts');
    } finally {
      setGenerating(false);
    }
  };

  const correlateAlerts = async () => {
    setCorrelating(true);
    try {
      const response = await api.post(`/incidents/correlate?company_id=${companyId}`);
      setCorrelationResult(response.data);
      toast.success(`Created ${response.data.incidents_created} incidents from ${response.data.total_alerts} alerts`);
      await loadAlerts();
    } catch (error) {
      console.error('Failed to correlate alerts:', error);
      toast.error('Failed to correlate alerts');
    } finally {
      setCorrelating(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      low: 'bg-slate-500/20 text-slate-300 border-slate-500/30',
      medium: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
      critical: 'bg-red-500/20 text-red-300 border-red-500/30'
    };
    return colors[severity] || colors.low;
  };

  const activeAlerts = alerts.filter(a => a.status === 'active');

  return (
    <div className="space-y-6" data-testid="alert-correlation">
      {/* Header */}
      <Card className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border-cyan-500/30">
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-white text-2xl flex items-center gap-3">
                <Zap className="w-6 h-6 text-cyan-400" />
                Alert Correlation Engine
              </CardTitle>
              <CardDescription className="text-slate-300 mt-2">
                Reduce noise by grouping duplicate alerts into correlated incidents
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            <Button
              onClick={generateAlerts}
              disabled={generating}
              className="bg-slate-700 hover:bg-slate-600 text-white"
              data-testid="generate-alerts-button"
            >
              {generating ? 'Generating...' : 'Generate 50 Sample Alerts'}
            </Button>
            <Button
              onClick={correlateAlerts}
              disabled={correlating || activeAlerts.length === 0}
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              data-testid="correlate-alerts-button"
            >
              <Play className="w-4 h-4 mr-2" />
              {correlating ? 'Correlating...' : 'Correlate Alerts'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Correlation Result */}
      {correlationResult && (
        <Card className="bg-slate-900/50 border-emerald-500/30" data-testid="correlation-result">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-emerald-400" />
              Correlation Complete
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-6">
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-3xl font-bold text-red-400" data-testid="total-alerts-count">{correlationResult.total_alerts}</p>
                <p className="text-sm text-slate-400 mt-1">Total Alerts</p>
              </div>
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-3xl font-bold text-cyan-400" data-testid="incidents-created-count">{correlationResult.incidents_created}</p>
                <p className="text-sm text-slate-400 mt-1">Incidents Created</p>
              </div>
              <div className="text-center p-4 bg-emerald-500/10 rounded-lg border border-emerald-500/30">
                <p className="text-3xl font-bold text-emerald-400" data-testid="noise-reduction-pct">{correlationResult.noise_reduction_pct}%</p>
                <p className="text-sm text-emerald-300 mt-1">Noise Reduction</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Active Alerts */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center justify-between">
            <span>Active Alerts ({activeAlerts.length})</span>
            {activeAlerts.length > 0 && (
              <Badge variant="outline" className="bg-red-500/20 text-red-300 border-red-500/30">
                <AlertCircle className="w-3 h-3 mr-1" />
                Unprocessed
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {activeAlerts.length === 0 ? (
            <div className="text-center py-12 text-slate-400">
              <CheckCircle className="w-12 h-12 mx-auto mb-4 text-slate-600" />
              <p>No active alerts. Generate some to test correlation.</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-[500px] overflow-y-auto" data-testid="active-alerts-list">
              {activeAlerts.slice(0, 20).map((alert) => (
                <div
                  key={alert.id}
                  className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors"
                  data-testid={`alert-${alert.id}`}
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge className={`text-xs ${getSeverityColor(alert.severity)} border`}>
                        {alert.severity}
                      </Badge>
                      <span className="text-sm font-medium text-white">{alert.asset_name}</span>
                    </div>
                    <p className="text-sm text-slate-400">{alert.message}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-slate-500">{alert.tool_source}</p>
                    <p className="text-xs text-slate-600">{new Date(alert.timestamp).toLocaleTimeString()}</p>
                  </div>
                </div>
              ))}
              {activeAlerts.length > 20 && (
                <p className="text-center text-slate-500 text-sm py-2">
                  ... and {activeAlerts.length - 20} more alerts
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default AlertCorrelation;