import React, { useState, useEffect } from 'react';
import { RefreshCw, CheckCircle, XCircle, AlertTriangle, Clock, Server, Package } from 'lucide-react';

const PatchCompliance = ({ companyId }) => {
  const [compliance, setCompliance] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [selectedEnv, setSelectedEnv] = useState('all');

  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '';

  useEffect(() => {
    fetchComplianceData();
    fetchSummary();
  }, [companyId]);

  const fetchComplianceData = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${BACKEND_URL}/api/companies/${companyId}/patch-compliance`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setCompliance(data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching patch compliance:', error);
      setLoading(false);
    }
  };

  const fetchSummary = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${BACKEND_URL}/api/patch-compliance/summary?company_id=${companyId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setSummary(data);
    } catch (error) {
      console.error('Error fetching summary:', error);
    }
  };

  const syncWithAWS = async () => {
    setSyncing(true);
    try {
      const token = localStorage.getItem('token');
      await fetch(`${BACKEND_URL}/api/patch-compliance/sync?company_id=${companyId}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      await fetchComplianceData();
      await fetchSummary();
    } catch (error) {
      console.error('Error syncing:', error);
    }
    setSyncing(false);
  };

  const getStatusBadge = (status) => {
    if (status === 'COMPLIANT') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
          <CheckCircle className="w-3 h-3" />
          Compliant
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20">
        <XCircle className="w-3 h-3" />
        Non-Compliant
      </span>
    );
  };

  const getEnvColor = (env) => {
    const colors = {
      production: 'text-red-400 bg-red-500/10 border-red-500/20',
      staging: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
      development: 'text-blue-400 bg-blue-500/10 border-blue-500/20'
    };
    return colors[env] || 'text-gray-400 bg-gray-500/10 border-gray-500/20';
  };

  const filteredCompliance = selectedEnv === 'all' 
    ? compliance 
    : compliance.filter(c => c.environment === selectedEnv);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Sync Button */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Patch Compliance</h2>
          <p className="text-gray-400 mt-1">AWS Patch Manager Integration</p>
        </div>
        <button
          onClick={syncWithAWS}
          disabled={syncing}
          className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${syncing ? 'animate-spin' : ''}`} />
          {syncing ? 'Syncing...' : 'Sync with AWS'}
        </button>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-gradient-to-br from-gray-800 to-gray-900 p-6 rounded-xl border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Compliance Rate</p>
                <p className="text-3xl font-bold text-white mt-2">
                  {summary.compliance_percentage}%
                </p>
              </div>
              <div className={`p-3 rounded-lg ${summary.compliance_percentage >= 95 ? 'bg-green-500/10' : 'bg-yellow-500/10'}`}>
                {summary.compliance_percentage >= 95 ? (
                  <CheckCircle className="w-8 h-8 text-green-400" />
                ) : (
                  <AlertTriangle className="w-8 h-8 text-yellow-400" />
                )}
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-2">
              {summary.compliant_instances} of {summary.total_instances} instances
            </p>
          </div>

          <div className="bg-gradient-to-br from-gray-800 to-gray-900 p-6 rounded-xl border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Critical Patches</p>
                <p className="text-3xl font-bold text-white mt-2">
                  {summary.total_critical_patches_missing}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-red-500/10">
                <AlertTriangle className="w-8 h-8 text-red-400" />
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-2">Missing across all instances</p>
          </div>

          <div className="bg-gradient-to-br from-gray-800 to-gray-900 p-6 rounded-xl border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">High Priority</p>
                <p className="text-3xl font-bold text-white mt-2">
                  {summary.total_high_patches_missing}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-orange-500/10">
                <Package className="w-8 h-8 text-orange-400" />
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-2">Patches pending</p>
          </div>

          <div className="bg-gradient-to-br from-gray-800 to-gray-900 p-6 rounded-xl border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Instances</p>
                <p className="text-3xl font-bold text-white mt-2">
                  {summary.total_instances}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-blue-500/10">
                <Server className="w-8 h-8 text-blue-400" />
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-2">Monitored servers</p>
          </div>
        </div>
      )}

      {/* Environment Filter */}
      <div className="flex items-center gap-2">
        <span className="text-gray-400 text-sm">Filter by environment:</span>
        {['all', 'production', 'staging', 'development'].map(env => (
          <button
            key={env}
            onClick={() => setSelectedEnv(env)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
              selectedEnv === env
                ? 'bg-cyan-500 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {env.charAt(0).toUpperCase() + env.slice(1)}
          </button>
        ))}
      </div>

      {/* Instance List */}
      <div className="bg-gray-800/50 rounded-xl border border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-900/50">
              <tr>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Instance
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Environment
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Compliance
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Missing Patches
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Last Scan
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {filteredCompliance.length === 0 ? (
                <tr>
                  <td colSpan="6" className="px-6 py-12 text-center">
                    <div className="flex flex-col items-center gap-3">
                      <Server className="w-12 h-12 text-gray-600" />
                      <p className="text-gray-400">No patch compliance data available</p>
                      <button
                        onClick={syncWithAWS}
                        className="text-cyan-400 hover:text-cyan-300 text-sm"
                      >
                        Sync with AWS to load data
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredCompliance.map((instance) => (
                  <tr key={instance.id} className="hover:bg-gray-700/30 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <Server className="w-5 h-5 text-gray-400" />
                        <div>
                          <p className="text-white font-medium">{instance.instance_name}</p>
                          <p className="text-xs text-gray-500">{instance.instance_id}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium border ${getEnvColor(instance.environment)}`}>
                        {instance.environment}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {getStatusBadge(instance.compliance_status)}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-gray-700 rounded-full h-2 max-w-[100px]">
                          <div
                            className={`h-2 rounded-full ${
                              instance.compliance_percentage >= 95
                                ? 'bg-green-500'
                                : instance.compliance_percentage >= 85
                                ? 'bg-yellow-500'
                                : 'bg-red-500'
                            }`}
                            style={{ width: `${instance.compliance_percentage}%` }}
                          />
                        </div>
                        <span className="text-sm text-white font-medium">
                          {instance.compliance_percentage.toFixed(1)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col gap-1">
                        {instance.critical_patches_missing > 0 && (
                          <span className="text-xs text-red-400">
                            {instance.critical_patches_missing} Critical
                          </span>
                        )}
                        {instance.high_patches_missing > 0 && (
                          <span className="text-xs text-orange-400">
                            {instance.high_patches_missing} High
                          </span>
                        )}
                        {instance.critical_patches_missing === 0 && instance.high_patches_missing === 0 && (
                          <span className="text-xs text-green-400">Up to date</span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2 text-gray-400 text-sm">
                        <Clock className="w-4 h-4" />
                        {new Date(instance.last_scan_time).toLocaleDateString()}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Environment Breakdown */}
      {summary && summary.by_environment && Object.keys(summary.by_environment).length > 0 && (
        <div className="bg-gray-800/50 rounded-xl border border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Compliance by Environment</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Object.entries(summary.by_environment).map(([env, stats]) => (
              <div key={env} className="bg-gray-900/50 p-4 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between mb-3">
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium border ${getEnvColor(env)}`}>
                    {env}
                  </span>
                  <span className="text-white font-semibold">
                    {stats.compliant}/{stats.total}
                  </span>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between text-gray-400">
                    <span>Compliance:</span>
                    <span className="text-white">
                      {((stats.compliant / stats.total) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between text-gray-400">
                    <span>Critical:</span>
                    <span className="text-red-400">{stats.critical_missing}</span>
                  </div>
                  <div className="flex justify-between text-gray-400">
                    <span>High:</span>
                    <span className="text-orange-400">{stats.high_missing}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default PatchCompliance;
