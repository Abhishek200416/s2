import React, { useState, useEffect } from 'react';
import { Shield, Key, Check, X, AlertCircle, Loader } from 'lucide-react';
import { api as API } from '../App';

const AWSCredentialsManager = ({ companyId }) => {
  const [credentials, setCredentials] = useState(null);
  const [loading, setLoading] = useState(false);
  const [testing, setTesting] = useState(false);
  const [formData, setFormData] = useState({
    access_key_id: '',
    secret_access_key: '',
    region: 'us-east-1'
  });
  const [testResult, setTestResult] = useState(null);
  const [showForm, setShowForm] = useState(false);

  useEffect(() => {
    loadCredentials();
  }, [companyId]);

  const loadCredentials = async () => {
    try {
      const response = await API.get(`/companies/${companyId}/aws-credentials`);
      setCredentials(response.data);
      setShowForm(false);
    } catch (error) {
      if (error.response?.status === 404) {
        setCredentials(null);
        setShowForm(true);
      }
    }
  };

  const handleSave = async () => {
    setLoading(true);
    setTestResult(null);
    try {
      await API.post(`/companies/${companyId}/aws-credentials`, formData);
      await loadCredentials();
      setFormData({ access_key_id: '', secret_access_key: '', region: 'us-east-1' });
      alert('AWS credentials saved successfully!');
    } catch (error) {
      alert('Failed to save credentials: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const response = await API.post(`/companies/${companyId}/aws-credentials/test`);
      setTestResult({ success: true, message: response.data.message });
    } catch (error) {
      setTestResult({ 
        success: false, 
        message: error.response?.data?.detail || 'Connection test failed' 
      });
    } finally {
      setTesting(false);
    }
  };

  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete AWS credentials? This will disable SSM operations.')) {
      return;
    }
    setLoading(true);
    try {
      await API.delete(`/companies/${companyId}/aws-credentials`);
      setCredentials(null);
      setShowForm(true);
      alert('AWS credentials deleted successfully');
    } catch (error) {
      alert('Failed to delete credentials: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <Shield className="w-6 h-6 text-cyan-400" />
          <div>
            <h3 className="text-xl font-semibold text-white">AWS Credentials</h3>
            <p className="text-sm text-gray-400">Manage client's AWS credentials for SSM operations</p>
          </div>
        </div>
        {credentials && (
          <div className="flex items-center space-x-2">
            <Check className="w-5 h-5 text-green-400" />
            <span className="text-sm text-green-400 font-medium">Configured</span>
          </div>
        )}
      </div>

      {credentials && !showForm ? (
        <div className="space-y-4">
          <div className="bg-gray-700/50 rounded-lg p-4 border border-gray-600">
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-sm text-gray-400">Region:</span>
                <span className="text-sm text-white font-mono">{credentials.region}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-400">Access Key:</span>
                <span className="text-sm text-white font-mono">{credentials.access_key_id_preview}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-400">Secret Key:</span>
                <span className="text-sm text-white font-mono">••••••••••••••••</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-400">Configured At:</span>
                <span className="text-sm text-white">{new Date(credentials.created_at).toLocaleString()}</span>
              </div>
            </div>
          </div>

          {testResult && (
            <div className={`flex items-start space-x-3 p-4 rounded-lg ${
              testResult.success 
                ? 'bg-green-500/10 border border-green-500/30' 
                : 'bg-red-500/10 border border-red-500/30'
            }`}>
              {testResult.success ? (
                <Check className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              )}
              <div className="flex-1">
                <p className={`text-sm font-medium ${
                  testResult.success ? 'text-green-400' : 'text-red-400'
                }`}>
                  {testResult.success ? 'Connection Successful' : 'Connection Failed'}
                </p>
                <p className="text-sm text-gray-300 mt-1">{testResult.message}</p>
              </div>
            </div>
          )}

          <div className="flex space-x-3">
            <button
              onClick={handleTest}
              disabled={testing}
              className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {testing ? (
                <Loader className="w-4 h-4 animate-spin" />
              ) : (
                <Shield className="w-4 h-4" />
              )}
              <span>{testing ? 'Testing...' : 'Test Connection'}</span>
            </button>
            <button
              onClick={() => setShowForm(true)}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
            >
              Update
            </button>
            <button
              onClick={handleDelete}
              disabled={loading}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              Delete
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <AlertCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
              <div className="text-sm text-blue-300">
                <p className="font-medium mb-1">Client AWS Credentials Required</p>
                <p className="text-blue-200">These credentials will be encrypted and used to execute SSM commands on this client's infrastructure.</p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                AWS Access Key ID
              </label>
              <input
                type="text"
                value={formData.access_key_id}
                onChange={(e) => setFormData({ ...formData, access_key_id: e.target.value })}
                placeholder="AKIA..."
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                AWS Secret Access Key
              </label>
              <input
                type="password"
                value={formData.secret_access_key}
                onChange={(e) => setFormData({ ...formData, secret_access_key: e.target.value })}
                placeholder="Enter secret key"
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                AWS Region
              </label>
              <select
                value={formData.region}
                onChange={(e) => setFormData({ ...formData, region: e.target.value })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-east-2">US East (Ohio)</option>
                <option value="us-west-1">US West (N. California)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">EU (Ireland)</option>
                <option value="eu-central-1">EU (Frankfurt)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                <option value="ap-southeast-2">Asia Pacific (Sydney)</option>
              </select>
            </div>
          </div>

          <div className="flex space-x-3">
            <button
              onClick={handleSave}
              disabled={loading || !formData.access_key_id || !formData.secret_access_key}
              className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <Loader className="w-4 h-4 animate-spin" />
              ) : (
                <Key className="w-4 h-4" />
              )}
              <span>{loading ? 'Saving...' : 'Save Credentials'}</span>
            </button>
            {credentials && (
              <button
                onClick={() => setShowForm(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default AWSCredentialsManager;