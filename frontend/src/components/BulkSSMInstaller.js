import React, { useState, useEffect } from 'react';
import { Server, Download, Loader, CheckCircle, XCircle, AlertCircle, RefreshCw } from 'lucide-react';
import { api as API } from '../App';

const BulkSSMInstaller = ({ companyId }) => {
  const [instances, setInstances] = useState([]);
  const [selectedInstances, setSelectedInstances] = useState([]);
  const [loading, setLoading] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [installationStatus, setInstallationStatus] = useState(null);

  useEffect(() => {
    if (companyId) {
      loadInstances();
    }
  }, [companyId]);

  const loadInstances = async () => {
    setLoading(true);
    try {
      const response = await API.get(`/companies/${companyId}/instances-without-ssm`);
      setInstances(response.data.instances || []);
      setSelectedInstances([]);
    } catch (error) {
      console.error('Failed to load instances:', error);
      alert('Failed to load instances: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleSelectAll = () => {
    if (selectedInstances.length === instances.length) {
      setSelectedInstances([]);
    } else {
      setSelectedInstances(instances.map(i => i.instance_id));
    }
  };

  const handleToggleInstance = (instanceId) => {
    setSelectedInstances(prev => 
      prev.includes(instanceId)
        ? prev.filter(id => id !== instanceId)
        : [...prev, instanceId]
    );
  };

  const handleBulkInstall = async () => {
    if (selectedInstances.length === 0) {
      alert('Please select at least one instance');
      return;
    }

    if (!window.confirm(`Install SSM agent on ${selectedInstances.length} instance(s)?`)) {
      return;
    }

    setInstalling(true);
    setInstallationStatus(null);
    try {
      const response = await API.post(`/companies/${companyId}/ssm/bulk-install`, {
        instance_ids: selectedInstances
      });
      
      const commandId = response.data.command_id;
      setInstallationStatus({
        command_id: commandId,
        status: 'InProgress',
        message: 'Installation started successfully'
      });

      // Poll for status
      pollInstallationStatus(commandId);
    } catch (error) {
      alert('Failed to start installation: ' + (error.response?.data?.detail || error.message));
      setInstalling(false);
    }
  };

  const pollInstallationStatus = async (commandId) => {
    let attempts = 0;
    const maxAttempts = 30; // 5 minutes max (10 sec intervals)

    const poll = async () => {
      attempts++;
      try {
        const response = await API.get(`/companies/${companyId}/ssm/installation-status/${commandId}`);
        const status = response.data;

        setInstallationStatus(status);

        if (status.status === 'Success' || status.status === 'Failed' || attempts >= maxAttempts) {
          setInstalling(false);
          if (status.status === 'Success') {
            await loadInstances(); // Reload to update list
          }
          return;
        }

        // Continue polling
        setTimeout(poll, 10000); // 10 seconds
      } catch (error) {
        console.error('Failed to check status:', error);
        setInstalling(false);
      }
    };

    poll();
  };

  const getPlatformIcon = (platform) => {
    if (platform?.toLowerCase().includes('windows')) return '🪟';
    if (platform?.toLowerCase().includes('amazon')) return '🐧';
    if (platform?.toLowerCase().includes('ubuntu')) return '🐧';
    return '💻';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-semibold text-white">Bulk SSM Agent Installer</h3>
          <p className="text-gray-400 mt-1">Install AWS SSM agents on multiple servers at once</p>
        </div>
        <button
          onClick={loadInstances}
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Installation Status */}
      {installationStatus && (
        <div className={`flex items-start space-x-3 p-4 rounded-lg ${
          installationStatus.status === 'Success' ? 'bg-green-500/10 border border-green-500/30' :
          installationStatus.status === 'Failed' ? 'bg-red-500/10 border border-red-500/30' :
          'bg-blue-500/10 border border-blue-500/30'
        }`}>
          {installationStatus.status === 'Success' ? (
            <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
          ) : installationStatus.status === 'Failed' ? (
            <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          ) : (
            <Loader className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5 animate-spin" />
          )}
          <div className="flex-1">
            <p className={`text-sm font-medium ${
              installationStatus.status === 'Success' ? 'text-green-400' :
              installationStatus.status === 'Failed' ? 'text-red-400' : 'text-blue-400'
            }`}>
              {installationStatus.status === 'Success' ? 'Installation Complete' :
               installationStatus.status === 'Failed' ? 'Installation Failed' : 'Installing...'}
            </p>
            <p className="text-sm text-gray-300 mt-1">{installationStatus.message}</p>
            {installationStatus.command_id && (
              <p className="text-xs text-gray-500 mt-1 font-mono">
                Command ID: {installationStatus.command_id}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Instances Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader className="w-8 h-8 animate-spin text-cyan-400" />
          </div>
        ) : instances.length === 0 ? (
          <div className="text-center py-12">
            <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-3" />
            <p className="text-gray-300 font-medium">All instances have SSM agent installed!</p>
            <p className="text-gray-500 text-sm mt-1">No instances found that need SSM agent installation</p>
          </div>
        ) : (
          <>
            <div className="bg-gray-700/50 px-6 py-4 border-b border-gray-600 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={selectedInstances.length === instances.length && instances.length > 0}
                  onChange={handleSelectAll}
                  className="rounded bg-gray-600 border-gray-500 text-cyan-600 focus:ring-cyan-500"
                />
                <span className="text-sm text-gray-300">
                  {selectedInstances.length === 0 ? (
                    `${instances.length} instance(s) without SSM agent`
                  ) : (
                    `${selectedInstances.length} of ${instances.length} selected`
                  )}
                </span>
              </div>
              {selectedInstances.length > 0 && (
                <button
                  onClick={handleBulkInstall}
                  disabled={installing}
                  className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {installing ? (
                    <Loader className="w-4 h-4 animate-spin" />
                  ) : (
                    <Download className="w-4 h-4" />
                  )}
                  <span>{installing ? 'Installing...' : `Install on ${selectedInstances.length} instance(s)`}</span>
                </button>
              )}
            </div>

            <div className="divide-y divide-gray-700">
              {instances.map(instance => (
                <div
                  key={instance.instance_id}
                  className="px-6 py-4 hover:bg-gray-700/30 transition-colors"
                >
                  <div className="flex items-center space-x-4">
                    <input
                      type="checkbox"
                      checked={selectedInstances.includes(instance.instance_id)}
                      onChange={() => handleToggleInstance(instance.instance_id)}
                      className="rounded bg-gray-600 border-gray-500 text-cyan-600 focus:ring-cyan-500"
                    />
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className="text-2xl">{getPlatformIcon(instance.platform)}</span>
                        <div>
                          <p className="font-medium text-white">{instance.name || 'Unnamed Instance'}</p>
                          <p className="text-sm text-gray-400 font-mono">{instance.instance_id}</p>
                        </div>
                      </div>
                      <div className="grid grid-cols-3 gap-4 text-sm">
                        <div>
                          <span className="text-gray-500">Platform:</span>
                          <span className="ml-2 text-gray-300">{instance.platform || 'Unknown'}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Type:</span>
                          <span className="ml-2 text-gray-300">{instance.instance_type || 'Unknown'}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">State:</span>
                          <span className={`ml-2 px-2 py-0.5 rounded text-xs font-medium ${
                            instance.state === 'running' ? 'bg-green-500/20 text-green-300' :
                            instance.state === 'stopped' ? 'bg-red-500/20 text-red-300' :
                            'bg-yellow-500/20 text-yellow-300'
                          }`}>
                            {instance.state}
                          </span>
                        </div>
                      </div>
                      {instance.private_ip && (
                        <p className="text-sm text-gray-500 mt-2">IP: {instance.private_ip}</p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Info Box */}
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
        <div className="flex items-start space-x-3">
          <AlertCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-blue-300">
            <p className="font-medium mb-2">How Bulk Installation Works:</p>
            <ul className="list-disc list-inside space-y-1 text-blue-200">
              <li>Uses AWS Systems Manager Distributor to install SSM agent</li>
              <li>Works on running instances only</li>
              <li>Installation takes 2-5 minutes per instance</li>
              <li>IAM instance profile must allow SSM access</li>
              <li>After installation, instances will appear in Agent Health dashboard</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BulkSSMInstaller;