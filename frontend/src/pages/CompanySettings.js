import React, { useState, useEffect } from 'react';
import { ArrowLeft, Building2 } from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';
import { api as API } from '../App';
import AWSCredentialsManager from '../components/AWSCredentialsManager';
import BulkSSMInstaller from '../components/BulkSSMInstaller';

const CompanySettings = () => {
  const navigate = useNavigate();
  const { companyId } = useParams();
  const [company, setCompany] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('aws');

  useEffect(() => {
    loadCompany();
  }, [companyId]);

  const loadCompany = async () => {
    try {
      const response = await API.get(`/companies/${companyId}`);
      setCompany(response.data);
    } catch (error) {
      console.error('Failed to load company:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-gray-400">Loading...</div>
      </div>
    );
  }

  if (!company) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-gray-400">Company not found</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center space-x-2 text-gray-400 hover:text-white transition-colors mb-4"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Dashboard</span>
          </button>
          
          <div className="flex items-center space-x-3">
            <Building2 className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-3xl font-bold text-white">{company.name}</h1>
              <p className="text-gray-400 mt-1">Company Settings & Infrastructure Management</p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 mb-6">
          <div className="flex border-b border-gray-700">
            <button
              onClick={() => setActiveTab('aws')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'aws'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              AWS Credentials
            </button>
            <button
              onClick={() => setActiveTab('ssm')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'ssm'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              SSM Agent Installer
            </button>
          </div>

          <div className="p-6">
            {activeTab === 'aws' && <AWSCredentialsManager companyId={companyId} />}
            {activeTab === 'ssm' && <BulkSSMInstaller companyId={companyId} />}
          </div>
        </div>

        {/* Info Box */}
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
          <h3 className="text-blue-300 font-medium mb-2">About Company Settings</h3>
          <ul className="text-sm text-blue-200 space-y-1">
            <li>• <strong>AWS Credentials:</strong> Store client's AWS credentials securely (encrypted) for SSM operations</li>
            <li>• <strong>SSM Agent Installer:</strong> Bulk install AWS SSM agents on client servers for remote management</li>
            <li>• <strong>Per-Client Isolation:</strong> Each client's credentials are stored separately and encrypted</li>
            <li>• <strong>Secure Operations:</strong> All SSM commands use the client's credentials, not your MSP credentials</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default CompanySettings;
