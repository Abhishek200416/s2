import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_BACKEND_URL || '';

function RunbookLibrary() {
  const [runbooks, setRunbooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterCategory, setFilterCategory] = useState('all');
  const [filterCloud, setFilterCloud] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRunbook, setSelectedRunbook] = useState(null);
  const [executeModal, setExecuteModal] = useState(false);
  const [instanceIds, setInstanceIds] = useState('');
  const [executing, setExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  const [companies, setCompanies] = useState([]);
  const [selectedCompany, setSelectedCompany] = useState('');

  useEffect(() => {
    fetchRunbooks();
    fetchCompanies();
  }, []);

  const fetchRunbooks = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_URL}/msp/runbooks`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setRunbooks(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching runbooks:', error);
      setLoading(false);
    }
  };

  const fetchCompanies = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_URL}/companies`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setCompanies(response.data);
      if (response.data.length > 0) {
        setSelectedCompany(response.data[0].id);
      }
    } catch (error) {
      console.error('Error fetching companies:', error);
    }
  };

  const executeRunbook = async () => {
    if (!selectedRunbook || !instanceIds.trim() || !selectedCompany) {
      alert('Please provide instance IDs and select a company');
      return;
    }

    setExecuting(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(
        `${API_URL}/msp/runbooks/${selectedRunbook.id}/execute`,
        {
          target_config: {
            instance_ids: instanceIds.split(',').map(id => id.trim()),
            company_id: selectedCompany
          }
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      setExecutionResult(response.data);
      setTimeout(() => {
        setExecuteModal(false);
        setExecutionResult(null);
        setInstanceIds('');
      }, 3000);
    } catch (error) {
      console.error('Error executing runbook:', error);
      alert('Execution failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setExecuting(false);
    }
  };

  const categories = ['all', 'disk', 'memory', 'cpu', 'network', 'application', 'database', 'security', 'monitoring'];
  const cloudProviders = ['all', 'aws', 'azure', 'multi'];

  const filteredRunbooks = runbooks.filter(rb => {
    const matchCategory = filterCategory === 'all' || rb.category === filterCategory;
    const matchCloud = filterCloud === 'all' || rb.cloud_provider === filterCloud;
    const matchSearch = searchTerm === '' || 
      rb.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rb.description.toLowerCase().includes(searchTerm.toLowerCase());
    return matchCategory && matchCloud && matchSearch;
  });

  const getRiskBadgeColor = (risk) => {
    switch(risk) {
      case 'low': return 'bg-green-100 text-green-800 border-green-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'high': return 'bg-red-100 text-red-800 border-red-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getCategoryIcon = (category) => {
    const icons = {
      disk: '💾',
      memory: '🧠',
      cpu: '⚡',
      network: '🌐',
      application: '📦',
      database: '🗄️',
      security: '🔒',
      monitoring: '📊'
    };
    return icons[category] || '📋';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading runbooks...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">📚 Runbook Library</h1>
            <p className="text-slate-400">Pre-built automation scripts for remote execution</p>
          </div>
          <button
            onClick={() => window.location.href = '/dashboard'}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
          >
            ← Back to Dashboard
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Search */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Search</label>
            <input
              type="text"
              placeholder="Search runbooks..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Category Filter */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Category</label>
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
            >
              {categories.map(cat => (
                <option key={cat} value={cat}>{cat.charAt(0).toUpperCase() + cat.slice(1)}</option>
              ))}
            </select>
          </div>

          {/* Cloud Provider Filter */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Cloud Provider</label>
            <select
              value={filterCloud}
              onChange={(e) => setFilterCloud(e.target.value)}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
            >
              {cloudProviders.map(cloud => (
                <option key={cloud} value={cloud}>{cloud.toUpperCase()}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-4 text-slate-400 text-sm">
          Showing {filteredRunbooks.length} of {runbooks.length} runbooks
        </div>
      </div>

      {/* Runbooks Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredRunbooks.map(runbook => (
          <div
            key={runbook.id}
            className="bg-slate-800 border border-slate-700 rounded-lg p-6 hover:border-cyan-500 transition-all cursor-pointer"
            onClick={() => {
              setSelectedRunbook(runbook);
              setExecuteModal(true);
            }}
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center space-x-3">
                <span className="text-3xl">{getCategoryIcon(runbook.category)}</span>
                <div>
                  <h3 className="text-lg font-semibold text-white">{runbook.name}</h3>
                  <p className="text-sm text-slate-400">{runbook.category}</p>
                </div>
              </div>
            </div>

            {/* Description */}
            <p className="text-slate-300 text-sm mb-4 line-clamp-2">
              {runbook.description}
            </p>

            {/* Badges */}
            <div className="flex flex-wrap gap-2 mb-4">
              <span className={`px-3 py-1 text-xs font-medium rounded-full border ${getRiskBadgeColor(runbook.risk_level)}`}>
                {runbook.risk_level.toUpperCase()} RISK
              </span>
              <span className="px-3 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-800 border border-blue-200">
                {runbook.cloud_provider.toUpperCase()}
              </span>
              {runbook.auto_approve && (
                <span className="px-3 py-1 text-xs font-medium rounded-full bg-green-100 text-green-800 border border-green-200">
                  AUTO-APPROVE
                </span>
              )}
            </div>

            {/* Stats */}
            <div className="flex items-center justify-between text-xs text-slate-400 pt-4 border-t border-slate-700">
              <span>Executed: {runbook.execution_count || 0} times</span>
              <span className="text-cyan-400 font-medium">Click to Execute →</span>
            </div>
          </div>
        ))}
      </div>

      {filteredRunbooks.length === 0 && (
        <div className="text-center py-12">
          <p className="text-slate-400 text-lg">No runbooks match your filters</p>
        </div>
      )}

      {/* Execute Modal */}
      {executeModal && selectedRunbook && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-slate-800 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto border border-slate-700">
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-700">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold text-white">Execute Runbook</h2>
                <button
                  onClick={() => {
                    setExecuteModal(false);
                    setExecutionResult(null);
                  }}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-6">
              {/* Runbook Info */}
              <div>
                <h3 className="text-xl font-semibold text-white mb-2">{selectedRunbook.name}</h3>
                <p className="text-slate-300 mb-4">{selectedRunbook.description}</p>
                
                <div className="flex flex-wrap gap-2">
                  <span className={`px-3 py-1 text-xs font-medium rounded-full border ${getRiskBadgeColor(selectedRunbook.risk_level)}`}>
                    {selectedRunbook.risk_level.toUpperCase()} RISK
                  </span>
                  <span className="px-3 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-800 border border-blue-200">
                    {selectedRunbook.script_type.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Company Selection */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Select Company *
                </label>
                <select
                  value={selectedCompany}
                  onChange={(e) => setSelectedCompany(e.target.value)}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="">Select a company</option>
                  {companies.map(company => (
                    <option key={company.id} value={company.id}>{company.name}</option>
                  ))}
                </select>
              </div>

              {/* Instance IDs Input */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  EC2 Instance IDs (comma-separated) *
                </label>
                <input
                  type="text"
                  placeholder="i-1234567890abcdef0, i-0987654321fedcba0"
                  value={instanceIds}
                  onChange={(e) => setInstanceIds(e.target.value)}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500"
                />
                <p className="text-xs text-slate-400 mt-1">
                  Enter one or more EC2 instance IDs where this script will be executed
                </p>
              </div>

              {/* Script Preview */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Script Preview</label>
                <pre className="bg-slate-900 border border-slate-700 rounded-lg p-4 text-sm text-green-400 overflow-x-auto max-h-64">
                  {selectedRunbook.script_content}
                </pre>
              </div>

              {/* Execution Result */}
              {executionResult && (
                <div className="bg-green-900 border border-green-700 rounded-lg p-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <span className="text-green-400 text-xl">✓</span>
                    <span className="text-green-300 font-semibold">Execution Started!</span>
                  </div>
                  <p className="text-green-200 text-sm">
                    Command ID: {executionResult.command_id}
                  </p>
                  <p className="text-green-200 text-sm">
                    Status: {executionResult.status}
                  </p>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex space-x-4">
                <button
                  onClick={executeRunbook}
                  disabled={executing || !instanceIds.trim() || !selectedCompany}
                  className="flex-1 px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-lg font-semibold hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {executing ? 'Executing...' : '🚀 Execute Runbook'}
                </button>
                <button
                  onClick={() => {
                    setExecuteModal(false);
                    setExecutionResult(null);
                  }}
                  className="px-6 py-3 bg-slate-700 text-white rounded-lg font-semibold hover:bg-slate-600 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default RunbookLibrary;
