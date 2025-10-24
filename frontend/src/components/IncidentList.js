import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { AlertTriangle, Eye, CheckCircle, Clock, XCircle, Zap, Settings } from 'lucide-react';
import { toast } from 'sonner';

const IncidentList = ({ companyId, limit, refreshTrigger }) => {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [showDecisionDialog, setShowDecisionDialog] = useState(false);
  const [decision, setDecision] = useState(null);
  const [loading, setLoading] = useState(false);
  const [autoDecideConfig, setAutoDecideConfig] = useState(null);
  const [loadingConfig, setLoadingConfig] = useState(true);
  const [autoDecideStats, setAutoDecideStats] = useState(null);

  useEffect(() => {
    if (companyId) {
      loadIncidents();
      loadAutoDecideConfig();
    }
  }, [companyId, refreshTrigger]);

  // Auto-decide timer effect
  useEffect(() => {
    if (!autoDecideConfig || !autoDecideConfig.enabled || loading || !companyId) {
      return;
    }

    const intervalMs = (autoDecideConfig.interval_seconds || 1) * 1000;
    
    const timer = setInterval(async () => {
      if (!loading) {
        const newIncidents = incidents.filter(i => i.status === 'new' && !i.decision);
        if (newIncidents.length > 0) {
          try {
            const response = await api.post(`/auto-decide/run?company_id=${companyId}`);
            setAutoDecideStats(response.data);
            await loadIncidents();
          } catch (error) {
            console.error('Auto-decide failed:', error);
          }
        }
      }
    }, intervalMs);

    return () => clearInterval(timer);
  }, [autoDecideConfig, companyId, loading, incidents]);

  const loadAutoDecideConfig = async () => {
    try {
      const response = await api.get(`/auto-decide/config?company_id=${companyId}`);
      setAutoDecideConfig(response.data);
    } catch (error) {
      console.error('Failed to load auto-decide config:', error);
    } finally {
      setLoadingConfig(false);
    }
  };

  const updateAutoDecideConfig = async (updates) => {
    try {
      const updatedConfig = { ...autoDecideConfig, ...updates };
      await api.put('/auto-decide/config', updatedConfig);
      setAutoDecideConfig(updatedConfig);
      toast.success('Auto-decide settings updated');
    } catch (error) {
      console.error('Failed to update auto-decide config:', error);
      toast.error('Failed to update settings');
    }
  };

  const loadIncidents = async () => {
    try {
      const response = await api.get(`/incidents?company_id=${companyId}`);
      let data = response.data;
      if (limit) {
        data = data.slice(0, limit);
      }
      setIncidents(data);
    } catch (error) {
      console.error('Failed to load incidents:', error);
    }
  };

  const viewDecision = async (incident) => {
    setSelectedIncident(incident);
    
    if (incident.decision) {
      // Already has decision, show it
      setDecision(incident.decision);
      setShowDecisionDialog(true);
    } else {
      // Auto-decide without opening dialog first
      setLoading(true);
      try {
        const response = await api.post(`/incidents/${incident.id}/decide`);
        setDecision(response.data);
        
        // Show immediate feedback based on decision
        if (response.data.auto_executed) {
          toast.success('Incident auto-resolved using runbook!');
        } else if (response.data.auto_assigned) {
          toast.success(`Incident assigned to ${response.data.assigned_to_name}`);
        } else {
          toast.success('Decision generated successfully');
        }
        
        // Reload incidents to show updated status
        await loadIncidents();
        
        // Show decision dialog
        setShowDecisionDialog(true);
      } catch (error) {
        console.error('Failed to generate decision:', error);
        toast.error('Failed to auto-decide incident');
      } finally {
        setLoading(false);
      }
    }
  };

  const approveIncident = async () => {
    if (!selectedIncident) return;
    
    setLoading(true);
    try {
      await api.post(`/incidents/${selectedIncident.id}/approve`);
      toast.success('Incident approved and executed');
      setShowDecisionDialog(false);
      await loadIncidents();
    } catch (error) {
      console.error('Failed to approve incident:', error);
      toast.error('Failed to approve incident');
    } finally {
      setLoading(false);
    }
  };

  const escalateIncident = async () => {
    if (!selectedIncident) return;
    
    setLoading(true);
    try {
      await api.post(`/incidents/${selectedIncident.id}/escalate`);
      toast.success('Incident escalated to technician');
      setShowDecisionDialog(false);
      await loadIncidents();
    } catch (error) {
      console.error('Failed to escalate incident:', error);
      toast.error('Failed to escalate incident');
    } finally {
      setLoading(false);
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

  const getStatusColor = (status) => {
    const colors = {
      new: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      in_progress: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      resolved: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      escalated: 'bg-purple-500/20 text-purple-300 border-purple-500/30'
    };
    return colors[status] || colors.new;
  };

  return (
    <div className="space-y-6">
      {/* Incidents List (full width) */}
      <div className="space-y-6">
        {/* Auto-Decide Configuration Card */}
        {!limit && !loadingConfig && autoDecideConfig && (
          <Card className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-purple-500/30">
            <CardContent className="pt-6">
              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Settings className="w-5 h-5 text-purple-400" />
                    <h3 className="text-white font-semibold">Auto-Decide Settings</h3>
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={autoDecideConfig.enabled}
                      onChange={(e) => updateAutoDecideConfig({ enabled: e.target.checked })}
                      className="w-4 h-4 rounded bg-slate-700 border-slate-600 text-purple-600 focus:ring-purple-500"
                    />
                    <span className="text-sm text-slate-300">Enable Auto-Decide</span>
                  </label>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm text-slate-300 font-medium mb-2 flex items-center gap-2">
                      <Clock className="w-4 h-4" />
                      Auto-Decide Interval
                    </label>
                    <Select
                      value={autoDecideConfig.interval_seconds?.toString()}
                      onValueChange={(value) => updateAutoDecideConfig({ interval_seconds: parseInt(value) })}
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
                      How often incidents are auto-decided (assigns or executes)
                    </p>
                  </div>
                  {autoDecideConfig.last_run && (
                    <div>
                      <label className="text-sm text-slate-300 font-medium mb-2 block">
                        Last Run
                      </label>
                      <div className="text-sm text-slate-400 bg-slate-900 border border-slate-700 rounded px-3 py-2">
                        {new Date(autoDecideConfig.last_run).toLocaleString()}
                      </div>
                    </div>
                  )}
                </div>

                {/* Auto-Decide Statistics */}
                {autoDecideStats && (
                  <div className="grid grid-cols-3 gap-3 pt-3 border-t border-slate-700">
                    <div className="text-center p-3 bg-slate-900/50 rounded-lg">
                      <p className="text-2xl font-bold text-purple-400">{autoDecideStats.incidents_processed}</p>
                      <p className="text-xs text-slate-400 mt-1">Processed</p>
                    </div>
                    <div className="text-center p-3 bg-slate-900/50 rounded-lg">
                      <p className="text-2xl font-bold text-cyan-400">{autoDecideStats.incidents_assigned}</p>
                      <p className="text-xs text-slate-400 mt-1">Assigned</p>
                    </div>
                    <div className="text-center p-3 bg-slate-900/50 rounded-lg">
                      <p className="text-2xl font-bold text-emerald-400">{autoDecideStats.incidents_executed}</p>
                      <p className="text-xs text-slate-400 mt-1">Auto-Executed</p>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        <Card className="bg-slate-900/50 border-slate-800" data-testid="incident-list">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              Incidents {!limit && `(${incidents.length})`}
            </CardTitle>
            {limit && (
              <CardDescription className="text-slate-400">Latest incidents requiring attention</CardDescription>
            )}
          </CardHeader>
          <CardContent>
          {incidents.length === 0 ? (
            <div className="text-center py-12 text-slate-400">
              <CheckCircle className="w-12 h-12 mx-auto mb-4 text-slate-600" />
              <p>No incidents found. Correlate alerts to create incidents.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {incidents.map((incident) => (
                <div
                  key={incident.id}
                  className="p-4 bg-slate-800/30 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors"
                  data-testid={`incident-${incident.id}`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge className={`text-xs ${getSeverityColor(incident.severity)} border`}>
                          {incident.severity}
                        </Badge>
                        <Badge className={`text-xs ${getStatusColor(incident.status)} border`}>
                          {incident.status.replace('_', ' ')}
                        </Badge>
                        {incident.priority_score > 0 && (
                          <span className="text-xs text-slate-500">Priority: {Math.round(incident.priority_score)}</span>
                        )}
                      </div>
                      <p className="text-sm font-medium text-white mb-1">
                        {incident.signature.replace(/_/g, ' ').replace(/:/g, ' - ')} on {incident.asset_name}
                      </p>
                      <p className="text-xs text-slate-400">
                        {incident.alert_count} correlated alert{incident.alert_count > 1 ? 's' : ''}
                      </p>
                    </div>
                    <Button
                      onClick={() => viewDecision(incident)}
                      size="sm"
                      variant="outline"
                      className="border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white"
                      data-testid={`view-decision-${incident.id}`}
                    >
                      <Eye className="w-4 h-4 mr-2" />
                      {incident.decision ? 'View' : 'Decide'}
                    </Button>
                  </div>
                  {incident.decision && (
                    <div className="mt-2 pt-3 border-t border-slate-700">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-500">Action:</span>
                        <Badge variant="outline" className="text-xs bg-cyan-500/10 text-cyan-300 border-cyan-500/30">
                          {incident.decision.action}
                        </Badge>
                        <span className="text-xs text-slate-400">{incident.decision.reason}</span>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      </div>

      {/* Decision Dialog */}
      <Dialog open={showDecisionDialog} onOpenChange={setShowDecisionDialog}>
        <DialogContent className="bg-slate-900 border-slate-800 text-white max-w-2xl">
          <DialogHeader>
            <DialogTitle className="text-lg">Incident Decision</DialogTitle>
            <DialogDescription className="text-slate-400">
              Automated remediation recommendation
            </DialogDescription>
          </DialogHeader>

          {decision && (
            <div className="space-y-4 mt-4">
              {/* AI Explanation */}
              {decision.ai_explanation && (
                <div className="p-4 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 rounded-lg border border-cyan-500/30">
                  <div className="flex items-start gap-2 mb-2">
                    <Zap className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <h4 className="text-sm font-semibold text-cyan-300">AI Recommendation</h4>
                  </div>
                  <p className="text-sm text-slate-200 leading-relaxed">{decision.ai_explanation}</p>
                </div>
              )}

              {/* Decision Summary */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <p className="text-xs text-slate-400 mb-1">Recommended Action</p>
                  <div className="flex items-center gap-2">
                    {decision.recommended_action === 'execute' ? (
                      <>
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <p className="text-sm font-semibold text-green-400">Execute Runbook</p>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        <p className="text-sm font-semibold text-amber-400">Escalate to Technician</p>
                      </>
                    )}
                  </div>
                </div>
                <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <p className="text-xs text-slate-400 mb-1">Priority Score</p>
                  <p className="text-sm font-semibold text-white">{Math.round(decision.priority_score || 0)}</p>
                </div>
              </div>

              {/* Runbook Information */}
              {decision.runbook_name && (
                <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <p className="text-xs text-slate-400 mb-1">Available Runbook</p>
                  <p className="text-sm font-medium text-white">{decision.runbook_name}</p>
                </div>
              )}

              {/* Technician Category */}
              {decision.recommended_technician_category && (
                <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <p className="text-xs text-slate-400 mb-1">Recommended Technician Category</p>
                  <Badge className="bg-purple-500/20 text-purple-300 border-purple-500/50">
                    {decision.recommended_technician_category}
                  </Badge>
                </div>
              )}

              {/* Reason */}
              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-xs text-slate-400 mb-1">Decision Reasoning</p>
                <p className="text-sm text-slate-300">{decision.reason}</p>
              </div>

              {/* Actions */}
              <div className="flex gap-3 pt-2">
                {decision.can_auto_execute && (
                  <Button
                    onClick={approveIncident}
                    disabled={loading}
                    className="bg-emerald-600 hover:bg-emerald-700 text-white flex-1"
                    data-testid="approve-button"
                  >
                    <CheckCircle className="w-4 h-4 mr-2" />
                    Execute Runbook
                  </Button>
                )}
                <Button
                  onClick={escalateIncident}
                  disabled={loading}
                  variant="outline"
                  className={`border-slate-700 hover:bg-slate-800 flex-1 ${
                    decision.can_auto_execute 
                      ? 'text-slate-300' 
                      : 'text-amber-300 border-amber-500/30 hover:bg-amber-500/10'
                  }`}
                  data-testid="escalate-button"
                >
                  <AlertTriangle className="w-4 h-4 mr-2" />
                  Escalate to Technician
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default IncidentList;