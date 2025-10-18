import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { AlertTriangle, Eye, CheckCircle, Clock, XCircle } from 'lucide-react';
import { toast } from 'sonner';

const IncidentList = ({ companyId, limit }) => {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [showDecisionDialog, setShowDecisionDialog] = useState(false);
  const [decision, setDecision] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (companyId) {
      loadIncidents();
    }
  }, [companyId]);

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
      setDecision(incident.decision);
      setShowDecisionDialog(true);
    } else {
      // Generate decision
      setLoading(true);
      try {
        const response = await api.post(`/incidents/${incident.id}/decide`);
        setDecision(response.data);
        setShowDecisionDialog(true);
        await loadIncidents();
      } catch (error) {
        console.error('Failed to generate decision:', error);
        toast.error('Failed to generate decision');
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
    <>
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
            <div className="space-y-3 mt-3">
              {/* AI Explanation */}
              {decision.ai_explanation && (
                <div className="p-3 bg-cyan-500/10 rounded-lg border border-cyan-500/30">
                  <p className="text-sm text-cyan-100 leading-relaxed">{decision.ai_explanation}</p>
                </div>
              )}

              {/* Key Decision Info - Compact Cards */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <p className="text-xs text-slate-400 mb-1">Action</p>
                  <p className="text-sm font-semibold text-white">{decision.action}</p>
                </div>
                <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <p className="text-xs text-slate-400 mb-1">Priority Score</p>
                  <p className="text-sm font-semibold text-white">{decision.priority_score || 'N/A'}</p>
                </div>
              </div>

              {/* Reason */}
              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-xs text-slate-400 mb-1">Reason</p>
                <p className="text-sm text-white">{decision.reason}</p>
              </div>

              {/* Collapsible Full JSON */}
              <details className="group">
                <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-300 py-2 px-3 bg-slate-800/30 rounded border border-slate-700">
                  <span className="group-open:hidden">▶ Show Full Details</span>
                  <span className="hidden group-open:inline">▼ Hide Full Details</span>
                </summary>
                <div className="mt-2 bg-slate-950 rounded-lg p-3 border border-slate-800 font-mono text-xs overflow-x-auto max-h-64 overflow-y-auto">
                  <pre className="text-slate-300">{JSON.stringify(decision, null, 2)}</pre>
                </div>
              </details>

              {/* Actions */}
              <div className="flex gap-3 pt-2">
                {decision.approval_required && (
                  <>
                    <Button
                      onClick={approveIncident}
                      disabled={loading}
                      className="bg-emerald-600 hover:bg-emerald-700 text-white flex-1"
                      data-testid="approve-button"
                    >
                      <CheckCircle className="w-4 h-4 mr-2" />
                      Execute
                    </Button>
                    <Button
                      onClick={escalateIncident}
                      disabled={loading}
                      variant="outline"
                      className="border-slate-700 text-slate-300 hover:bg-slate-800 flex-1"
                      data-testid="escalate-button"
                    >
                      <XCircle className="w-4 h-4 mr-2" />
                      Assign to Technician
                    </Button>
                  </>
                )}
                {!decision.approval_required && (
                  <Button
                    onClick={() => setShowDecisionDialog(false)}
                    className="bg-slate-700 hover:bg-slate-600 text-white w-full"
                  >
                    Close
                  </Button>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
};

export default IncidentList;