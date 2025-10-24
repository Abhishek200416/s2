import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Zap, Play, TrendingDown, CheckCircle, AlertCircle, Settings, Clock, Filter } from 'lucide-react';
import { toast } from 'sonner';

const AlertCorrelation = ({ companyId, companyName, refreshTrigger }) => {
  const [correlating, setCorrelating] = useState(false);
  const [activeAlerts, setActiveAlerts] = useState([]);
  const [correlationResult, setCorrelationResult] = useState(null);
  const [correlationStats, setCorrelationStats] = useState(null);
  const [autoCorrelationConfig, setAutoCorrelationConfig] = useState(null);
  const [loadingConfig, setLoadingConfig] = useState(true);

  useEffect(() => {
    loadAlerts();
    loadAutoCorrelationConfig();
  }, [companyId, refreshTrigger]);

  // Auto-correlation timer effect
  useEffect(() => {
    if (!autoCorrelationConfig || !autoCorrelationConfig.enabled || correlating) {
      return;
    }

    const intervalMs = (autoCorrelationConfig.interval_seconds || 1) * 1000;
    
    const timer = setInterval(async () => {
      if (!correlating && activeAlerts.length > 0) {
        try {
          const response = await api.post(`/auto-correlation/run?company_id=${companyId}`);
          setCorrelationStats(response.data);
          await loadAlerts();
        } catch (error) {
          console.error('Auto-correlation failed:', error);
        }
      }
    }, intervalMs);

    return () => clearInterval(timer);
  }, [autoCorrelationConfig, companyId, correlating, activeAlerts.length]);

  const loadAlerts = async () => {
    try {
      const response = await api.get(`/alerts?company_id=${companyId}&status=active`);
      setActiveAlerts(response.data);
    } catch (error) {
      console.error('Failed to load alerts:', error);
      toast.error('Failed to load alerts');
    }
  };

  const loadAutoCorrelationConfig = async () => {
    try {
      const response = await api.get(`/auto-correlation/config?company_id=${companyId}`);
      setAutoCorrelationConfig(response.data);
    } catch (error) {
      console.error('Failed to load auto-correlation config:', error);
    } finally {
      setLoadingConfig(false);
    }
  };

  const updateAutoCorrelationConfig = async (updates) => {
    try {
      const updatedConfig = { ...autoCorrelationConfig, ...updates };
      await api.put('/auto-correlation/config', updatedConfig);
      setAutoCorrelationConfig(updatedConfig);
      toast.success('Auto-correlation settings updated');
    } catch (error) {
      console.error('Failed to update auto-correlation config:', error);
      toast.error('Failed to update settings');
    }
  };

  const correlateAlerts = async () => {
    setCorrelating(true);
    try {
      // Use the new endpoint that returns statistics
      const response = await api.post(`/auto-correlation/run?company_id=${companyId}`);
      setCorrelationStats(response.data);
      
      toast.success(`Correlation complete: ${response.data.incidents_created} incidents created`);
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

  return (
    <div className="space-y-6" data-testid="alert-correlation">
      {/* Correlation Controls & Alerts (full width) */}
      <div className="space-y-6">
        {/* Header with Auto-Correlation Settings */}
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
          <CardContent className="space-y-4">
          {/* Auto-Correlation Settings */}
          {!loadingConfig && autoCorrelationConfig && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Settings className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-white font-semibold">Auto-Correlation Settings</h3>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={autoCorrelationConfig.enabled}
                    onChange={(e) => updateAutoCorrelationConfig({ enabled: e.target.checked })}
                    className="w-4 h-4 rounded bg-slate-700 border-slate-600 text-cyan-600 focus:ring-cyan-500"
                  />
                  <span className="text-sm text-slate-300">Enable Auto-Run</span>
                </label>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-slate-300 font-medium mb-2 flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    Auto-Run Interval
                  </label>
                  <Select
                    value={autoCorrelationConfig.interval_seconds?.toString()}
                    onValueChange={(value) => updateAutoCorrelationConfig({ interval_seconds: parseInt(value) })}
                  >
                    <SelectTrigger className="bg-slate-900 border-slate-700 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-700 text-white">
                      <SelectItem value="1">Every 1 second (Real-time)</SelectItem>
                      <SelectItem value="5">Every 5 seconds</SelectItem>
                      <SelectItem value="10">Every 10 seconds</SelectItem>
                      <SelectItem value="15">Every 15 seconds</SelectItem>
                      <SelectItem value="30">Every 30 seconds</SelectItem>
                      <SelectItem value="60">Every 1 minute</SelectItem>
                      <SelectItem value="120">Every 2 minutes</SelectItem>
                      <SelectItem value="300">Every 5 minutes</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-slate-500 mt-1">
                    How often correlation runs automatically (real-time analysis)
                  </p>
                </div>
                {autoCorrelationConfig.last_run && (
                  <div>
                    <label className="text-sm text-slate-300 font-medium mb-2 block">
                      Last Run
                    </label>
                    <div className="text-sm text-slate-400 bg-slate-900 border border-slate-700 rounded px-3 py-2">
                      {new Date(autoCorrelationConfig.last_run).toLocaleString()}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Manual Correlation Button */}
          <div className="flex gap-3">
            <Button
              onClick={correlateAlerts}
              disabled={correlating || activeAlerts.length === 0}
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              data-testid="correlate-alerts-button"
            >
              <Play className="w-4 h-4 mr-2" />
              {correlating ? 'Correlating...' : 'Run Correlation Now'}
            </Button>
            <span className="text-sm text-slate-400 flex items-center">
              {activeAlerts.length} active alerts ready for correlation
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Correlation Statistics */}
      {correlationStats && (
        <Card className="bg-slate-900/50 border-emerald-500/30" data-testid="correlation-result">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-emerald-400" />
              Correlation Results
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-3xl font-bold text-cyan-400">{correlationStats.alerts_before}</p>
                <p className="text-sm text-slate-400 mt-1">Alerts Before</p>
              </div>
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-3xl font-bold text-orange-400">{correlationStats.alerts_after}</p>
                <p className="text-sm text-slate-400 mt-1">Alerts After</p>
              </div>
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-3xl font-bold text-purple-400">{correlationStats.incidents_created}</p>
                <p className="text-sm text-slate-400 mt-1">Incidents Created</p>
              </div>
              <div className="text-center p-4 bg-emerald-500/10 rounded-lg border border-emerald-500/30">
                <p className="text-3xl font-bold text-emerald-400">{correlationStats.alerts_correlated}</p>
                <p className="text-sm text-emerald-300 mt-1">Noise Removed</p>
              </div>
            </div>

            {/* Additional Stats */}
            <div className="mt-4 grid grid-cols-2 gap-4">
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-amber-300 font-medium">Duplicates Found</span>
                  <span className="text-2xl font-bold text-amber-400">{correlationStats.duplicates_found || 0}</span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  {correlationStats.duplicate_groups || 0} duplicate groups identified
                </p>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-blue-300 font-medium">Noise Reduction</span>
                  <span className="text-2xl font-bold text-blue-400">
                    {correlationStats.alerts_before > 0 
                      ? Math.round((correlationStats.alerts_correlated / correlationStats.alerts_before) * 100)
                      : 0}%
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Reduction in alert volume
                </p>
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
                <p className="text-center text-sm text-slate-500 pt-2">
                  Showing 20 of {activeAlerts.length} alerts
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
      </div>
    </div>
  );
};

export default AlertCorrelation;
