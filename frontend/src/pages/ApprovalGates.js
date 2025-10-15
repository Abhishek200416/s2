import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';

const ApprovalGates = () => {
  const [approvalRequests, setApprovalRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [approvalNotes, setApprovalNotes] = useState('');

  useEffect(() => {
    loadApprovalRequests();
  }, []);

  const loadApprovalRequests = async () => {
    try {
      const response = await api.get('/approval-requests?status=pending');
      setApprovalRequests(response.data);
    } catch (error) {
      console.error('Failed to load approval requests:', error);
      toast.error('Failed to load approval requests');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (requestId) => {
    try {
      await api.post(`/approval-requests/${requestId}/approve`, {
        approval_notes: approvalNotes
      });
      toast.success('Runbook execution approved');
      await loadApprovalRequests();
      setSelectedRequest(null);
      setApprovalNotes('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to approve request');
    }
  };

  const handleReject = async (requestId) => {
    if (!approvalNotes) {
      toast.error('Please provide a reason for rejection');
      return;
    }
    try {
      await api.post(`/approval-requests/${requestId}/reject`, {
        rejection_reason: approvalNotes
      });
      toast.success('Runbook execution rejected');
      await loadApprovalRequests();
      setSelectedRequest(null);
      setApprovalNotes('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to reject request');
    }
  };

  const getRiskBadgeColor = (riskLevel) => {
    if (riskLevel === 'high') return 'bg-red-500/20 text-red-300 border-red-500/30';
    if (riskLevel === 'medium') return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
    return 'bg-green-500/20 text-green-300 border-green-500/30';
  };

  const getRiskIcon = (riskLevel) => {
    if (riskLevel === 'high') return <AlertTriangle className="w-4 h-4 text-red-400" />;
    if (riskLevel === 'medium') return <Shield className="w-4 h-4 text-orange-400" />;
    return <CheckCircle className="w-4 h-4 text-green-400" />;
  };

  if (loading) {
    return <div className="text-white text-center py-8">Loading approval requests...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Overview Card */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Approval Gates for Runbook Execution
          </CardTitle>
          <CardDescription className="text-slate-300">
            Risk-based approval workflow ensures dangerous operations require human authorization
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 bg-green-500/10 rounded-lg border border-green-500/30">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <h3 className="text-white font-semibold">Low Risk</h3>
              </div>
              <p className="text-sm text-slate-300 mb-2">Auto-executed immediately</p>
              <p className="text-xs text-slate-400">
                Safe operations like restarting services, clearing caches
              </p>
            </div>

            <div className="p-4 bg-orange-500/10 rounded-lg border border-orange-500/30">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="w-5 h-5 text-orange-400" />
                <h3 className="text-white font-semibold">Medium Risk</h3>
              </div>
              <p className="text-sm text-slate-300 mb-2">Requires Company/MSP Admin</p>
              <p className="text-xs text-slate-400">
                Configuration changes, scaling operations
              </p>
            </div>

            <div className="p-4 bg-red-500/10 rounded-lg border border-red-500/30">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <h3 className="text-white font-semibold">High Risk</h3>
              </div>
              <p className="text-sm text-slate-300 mb-2">MSP Admin approval only</p>
              <p className="text-xs text-slate-400">
                Data deletion, infrastructure changes, security updates
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Pending Requests */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" />
            Pending Approval Requests ({approvalRequests.length})
          </CardTitle>
          <CardDescription className="text-slate-300">
            Review and approve or reject runbook execution requests
          </CardDescription>
        </CardHeader>
        <CardContent>
          {approvalRequests.length === 0 ? (
            <div className="text-center py-12 text-slate-400">
              <CheckCircle className="w-16 h-16 mx-auto mb-4 text-slate-600" />
              <p className="text-lg">No pending approval requests</p>
              <p className="text-sm mt-2">All runbook executions are approved or auto-executed</p>
            </div>
          ) : (
            <div className="space-y-4">
              {approvalRequests.map((request) => (
                <div key={request.id} className="p-4 bg-slate-800/30 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        {getRiskIcon(request.risk_level)}
                        <span className={`px-2 py-1 rounded text-xs font-medium border ${getRiskBadgeColor(request.risk_level)}`}>
                          {request.risk_level.toUpperCase()} RISK
                        </span>
                        <span className="text-slate-400 text-xs">
                          {new Date(request.created_at).toLocaleString()}
                        </span>
                      </div>
                      <h3 className="text-white font-medium">Incident: {request.incident_id}</h3>
                      <p className="text-sm text-slate-400 mt-1">Runbook: {request.runbook_id}</p>
                      <p className="text-xs text-slate-500 mt-1">Requested by: User {request.requested_by}</p>
                    </div>
                  </div>

                  {selectedRequest === request.id ? (
                    <div className="space-y-3 mt-4 pt-4 border-t border-slate-700">
                      <div>
                        <label className="text-white text-sm font-medium block mb-2">
                          Approval/Rejection Notes
                        </label>
                        <textarea
                          value={approvalNotes}
                          onChange={(e) => setApprovalNotes(e.target.value)}
                          className="w-full bg-slate-800 border border-slate-700 rounded-lg p-3 text-white text-sm"
                          rows="3"
                          placeholder="Add notes about your decision..."
                        />
                      </div>
                      <div className="flex gap-2">
                        <Button
                          onClick={() => handleApprove(request.id)}
                          className="bg-green-500/20 border border-green-500/30 text-green-400 hover:bg-green-500/30"
                        >
                          <CheckCircle className="w-4 h-4 mr-2" />
                          Approve & Execute
                        </Button>
                        <Button
                          onClick={() => handleReject(request.id)}
                          variant="outline"
                          className="bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20"
                        >
                          <XCircle className="w-4 h-4 mr-2" />
                          Reject
                        </Button>
                        <Button
                          onClick={() => {
                            setSelectedRequest(null);
                            setApprovalNotes('');
                          }}
                          variant="outline"
                          className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex gap-2 mt-4">
                      <Button
                        onClick={() => setSelectedRequest(request.id)}
                        className="bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/30"
                      >
                        Review Request
                      </Button>
                    </div>
                  )}

                  {/* Expiration warning */}
                  {new Date(request.expires_at) < new Date(Date.now() + 30 * 60 * 1000) && (
                    <div className="mt-3 p-2 bg-orange-500/10 border border-orange-500/30 rounded text-sm text-orange-300 flex items-center gap-2">
                      <Clock className="w-4 h-4" />
                      Expires soon: {new Date(request.expires_at).toLocaleString()}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Best Practices */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Approval Best Practices</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm text-slate-300">
            <div className="flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              <p><strong className="text-white">Review runbook actions</strong> before approving to understand impact</p>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              <p><strong className="text-white">Verify incident context</strong> to ensure runbook matches the problem</p>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              <p><strong className="text-white">Add detailed notes</strong> documenting your approval decision</p>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              <p><strong className="text-white">Monitor execution</strong> after approval to catch issues early</p>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              <p><strong className="text-white">High-risk runbooks</strong> should have peer review when possible</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ApprovalGates;
