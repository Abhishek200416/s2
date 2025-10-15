import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Clock, UserCheck, AlertCircle, CheckCircle, XCircle } from 'lucide-react';
import { toast } from 'sonner';

const RBACSettings = ({ companyId }) => {
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditSummary, setAuditSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (companyId) {
      loadAuditLogs();
    }
  }, [companyId]);

  const loadAuditLogs = async () => {
    try {
      const [logsRes, summaryRes] = await Promise.all([
        api.get(`/audit-logs?company_id=${companyId}&limit=50`),
        api.get(`/audit-logs/summary?company_id=${companyId}`)
      ]);
      setAuditLogs(logsRes.data);
      setAuditSummary(summaryRes.data);
    } catch (error) {
      console.error('Failed to load audit logs:', error);
      toast.error('Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  const getActionIcon = (action) => {
    if (action.includes('approved') || action.includes('success')) {
      return <CheckCircle className="w-4 h-4 text-green-400" />;
    }
    if (action.includes('rejected') || action.includes('failed')) {
      return <XCircle className="w-4 h-4 text-red-400" />;
    }
    return <AlertCircle className="w-4 h-4 text-cyan-400" />;
  };

  const getActionBadgeColor = (action) => {
    if (action === 'runbook_executed') return 'bg-cyan-500/20 text-cyan-300';
    if (action === 'approval_granted') return 'bg-green-500/20 text-green-300';
    if (action === 'approval_rejected') return 'bg-red-500/20 text-red-300';
    if (action === 'incident_assigned') return 'bg-blue-500/20 text-blue-300';
    if (action === 'rate_limit_updated') return 'bg-orange-500/20 text-orange-300';
    return 'bg-slate-500/20 text-slate-300';
  };

  if (loading) {
    return <div className="text-white text-center py-8">Loading audit logs...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      {auditSummary && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-gradient-to-br from-cyan-500/10 to-slate-900/50 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-300">Total Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-white">{auditSummary.total_logs}</div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-br from-green-500/10 to-slate-900/50 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-300">Runbooks Executed</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-white">
                {auditSummary.action_counts.runbook_executed || 0}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-br from-blue-500/10 to-slate-900/50 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-300">Approvals</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-white">
                {(auditSummary.action_counts.approval_granted || 0) + (auditSummary.action_counts.approval_rejected || 0)}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-br from-orange-500/10 to-slate-900/50 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-300">Config Changes</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-white">
                {auditSummary.action_counts.rate_limit_updated || 0}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* RBAC Roles Card */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <UserCheck className="w-5 h-5 text-cyan-400" />
            Role-Based Access Control (RBAC)
          </CardTitle>
          <CardDescription className="text-slate-300">
            User roles and their permissions in the Alert Whisperer system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* MSP Admin */}
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <h3 className="text-white font-semibold mb-2 flex items-center gap-2">
                <Shield className="w-5 h-5 text-purple-400" />
                MSP Admin
              </h3>
              <p className="text-slate-300 text-sm mb-3">Full system access for MSP administrators</p>
              <div className="space-y-1 text-sm text-slate-400">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>View and manage all companies</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Execute all runbooks (low, medium, high risk)</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Approve high-risk runbook requests</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Manage users and technicians</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>View all audit logs</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Configure rate limits and security settings</span>
                </div>
              </div>
            </div>

            {/* Company Admin */}
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <h3 className="text-white font-semibold mb-2 flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-400" />
                Company Admin
              </h3>
              <p className="text-slate-300 text-sm mb-3">Manage specific company operations</p>
              <div className="space-y-1 text-sm text-slate-400">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>View incidents and alerts for assigned companies</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Assign incidents to technicians</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Execute low and medium risk runbooks</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Approve medium-risk runbook requests</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Manage technicians within company</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>View audit logs for assigned companies</span>
                </div>
              </div>
            </div>

            {/* Technician */}
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <h3 className="text-white font-semibold mb-2 flex items-center gap-2">
                <Shield className="w-5 h-5 text-green-400" />
                Technician
              </h3>
              <p className="text-slate-300 text-sm mb-3">Handle assigned incidents and alerts</p>
              <div className="space-y-1 text-sm text-slate-400">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>View assigned incidents and alerts</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Update incident status and notes</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span>Execute low-risk runbooks only</span>
                </div>
                <div className="flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span>Cannot approve runbooks (requires admin)</span>
                </div>
                <div className="flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span>Cannot manage users or configure settings</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Audit Log */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" />
            Audit Log
          </CardTitle>
          <CardDescription className="text-slate-300">
            Complete history of all critical operations and changes
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {auditLogs.length === 0 ? (
              <div className="text-center py-8 text-slate-400">
                No audit logs yet
              </div>
            ) : (
              auditLogs.map((log) => (
                <div key={log.id} className="p-3 bg-slate-800/30 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      {getActionIcon(log.action)}
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getActionBadgeColor(log.action)}`}>
                            {log.action.replace(/_/g, ' ').toUpperCase()}
                          </span>
                          <span className="text-slate-400 text-xs">
                            {new Date(log.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-white text-sm mb-1">
                          {log.user_email || 'System'} ({log.user_role || 'system'})
                        </p>
                        {log.details && Object.keys(log.details).length > 0 && (
                          <div className="text-xs text-slate-400 mt-2">
                            {Object.entries(log.details).slice(0, 3).map(([key, value]) => (
                              <div key={key} className="mb-1">
                                <span className="text-slate-500">{key}:</span>{' '}
                                <span className="text-slate-300">{typeof value === 'object' ? JSON.stringify(value).substring(0, 50) + '...' : value}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                    <span className={`text-xs font-medium ${log.status === 'success' ? 'text-green-400' : 'text-red-400'}`}>
                      {log.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default RBACSettings;
