import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Building2, Plus, Edit, Trash2, Server, Key, Copy, Check, Send, Code } from 'lucide-react';
import { toast } from 'sonner';

const CompanyManagement = ({ onCompanyChange }) => {
  const [companies, setCompanies] = useState([]);
  const [companyKPIs, setCompanyKPIs] = useState({});
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showIntegrationDialog, setShowIntegrationDialog] = useState(false);
  const [selectedCompany, setSelectedCompany] = useState(null);
  const [newlyCreatedCompany, setNewlyCreatedCompany] = useState(null);
  const [copiedItem, setCopiedItem] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    policy: { auto_approve_low_risk: true, maintenance_window: 'Sat 22:00-02:00' },
    assets: []
  });
  const [assetForm, setAssetForm] = useState({ id: '', name: '', type: '', os: '' });

  useEffect(() => {
    loadCompanies();
  }, []);

  const loadCompanies = async () => {
    try {
      const response = await api.get('/companies');
      setCompanies(response.data);
      // Load KPIs for each company
      response.data.forEach(company => loadCompanyKPIs(company.id));
    } catch (error) {
      console.error('Failed to load companies:', error);
    }
  };

  const loadCompanyKPIs = async (companyId) => {
    try {
      const response = await api.get(`/metrics/realtime?company_id=${companyId}`);
      setCompanyKPIs(prev => ({
        ...prev,
        [companyId]: response.data.kpis
      }));
    } catch (error) {
      console.error(`Failed to load KPIs for company ${companyId}:`, error);
    }
  };

  const createCompany = async () => {
    try {
      const response = await api.post('/companies', formData);
      const createdCompany = response.data;
      toast.success('Company created successfully');
      setShowCreateDialog(false);
      resetForm();
      await loadCompanies();
      
      // Show integration dialog with API key
      setNewlyCreatedCompany(createdCompany);
      setShowIntegrationDialog(true);
      
      if (onCompanyChange) onCompanyChange();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create company');
    }
  };

  const updateCompany = async () => {
    try {
      await api.put(`/companies/${selectedCompany.id}`, formData);
      toast.success('Company updated successfully');
      setShowEditDialog(false);
      resetForm();
      await loadCompanies();
      if (onCompanyChange) onCompanyChange();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update company');
    }
  };

  const deleteCompany = async (companyId, companyName) => {
    if (!window.confirm(`Are you sure you want to delete ${companyName}? This will remove all associated data.`)) {
      return;
    }

    try {
      await api.delete(`/companies/${companyId}`);
      toast.success('Company deleted successfully');
      await loadCompanies();
      if (onCompanyChange) onCompanyChange();
    } catch (error) {
      toast.error('Failed to delete company');
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      policy: { auto_approve_low_risk: true, maintenance_window: 'Sat 22:00-02:00' },
      assets: []
    });
    setSelectedCompany(null);
  };

  const addAsset = () => {
    if (!assetForm.name || !assetForm.type) {
      toast.error('Please fill asset name and type');
      return;
    }

    const asset = {
      id: assetForm.id || `asset-${Date.now()}`,
      name: assetForm.name,
      type: assetForm.type,
      os: assetForm.os
    };

    setFormData(prev => ({
      ...prev,
      assets: [...prev.assets, asset]
    }));

    setAssetForm({ id: '', name: '', type: '', os: '' });
    toast.success('Asset added');
  };

  const removeAsset = (index) => {
    setFormData(prev => ({
      ...prev,
      assets: prev.assets.filter((_, i) => i !== index)
    }));
  };

  const openEditDialog = (company) => {
    setSelectedCompany(company);
    setFormData({
      name: company.name,
      policy: company.policy,
      assets: company.assets
    });
    setShowEditDialog(true);
  };

  const viewIntegration = (company) => {
    setNewlyCreatedCompany(company);
    setShowIntegrationDialog(true);
  };

  const handleCopy = async (text, itemName) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedItem(itemName);
      toast.success('Copied to clipboard');
      setTimeout(() => setCopiedItem(null), 2000);
    } catch (error) {
      toast.error('Failed to copy');
    }
  };

  const backendUrl = process.env.REACT_APP_BACKEND_URL || window.location.origin;
  const webhookUrl = `${backendUrl}/api/webhooks/alerts`;

  return (
    <div className="space-y-6" data-testid="company-management">
      <Card className="bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border-blue-500/30">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-white text-2xl flex items-center gap-3">
                <Building2 className="w-6 h-6 text-blue-400" />
                Company Management
              </CardTitle>
              <CardDescription className="text-slate-300 mt-2">
                Manage MSP client companies, assets, and policies
              </CardDescription>
            </div>
            <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
              <DialogTrigger asChild>
                <Button className="bg-blue-600 hover:bg-blue-700 text-white" data-testid="create-company-button">
                  <Plus className="w-4 h-4 mr-2" />
                  Add Company
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-slate-900 border-slate-800 text-white max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Create New Company</DialogTitle>
                  <DialogDescription className="text-slate-400">Add a new MSP client company</DialogDescription>
                </DialogHeader>
                <div className="space-y-4 mt-4">
                  <div>
                    <Label>Company Name</Label>
                    <Input
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      placeholder="e.g., Acme Corp"
                      className="bg-slate-800 border-slate-700 text-white"
                    />
                  </div>

                  <div>
                    <Label>Maintenance Window</Label>
                    <Input
                      value={formData.policy.maintenance_window}
                      onChange={(e) => setFormData({
                        ...formData,
                        policy: { ...formData.policy, maintenance_window: e.target.value }
                      })}
                      placeholder="e.g., Sat 22:00-02:00"
                      className="bg-slate-800 border-slate-700 text-white"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Assets (Optional)</Label>
                    <div className="grid grid-cols-4 gap-2">
                      <Input
                        placeholder="Name"
                        value={assetForm.name}
                        onChange={(e) => setAssetForm({ ...assetForm, name: e.target.value })}
                        className="bg-slate-800 border-slate-700 text-white"
                      />
                      <Input
                        placeholder="Type"
                        value={assetForm.type}
                        onChange={(e) => setAssetForm({ ...assetForm, type: e.target.value })}
                        className="bg-slate-800 border-slate-700 text-white"
                      />
                      <Input
                        placeholder="OS"
                        value={assetForm.os}
                        onChange={(e) => setAssetForm({ ...assetForm, os: e.target.value })}
                        className="bg-slate-800 border-slate-700 text-white"
                      />
                      <Button onClick={addAsset} size="sm" className="bg-cyan-600 hover:bg-cyan-700">
                        <Plus className="w-4 h-4" />
                      </Button>
                    </div>

                    {formData.assets.length > 0 && (
                      <div className="mt-2 space-y-1">
                        {formData.assets.map((asset, index) => (
                          <div key={index} className="flex items-center justify-between p-2 bg-slate-800 rounded">
                            <span className="text-sm text-white">{asset.name} - {asset.type} ({asset.os})</span>
                            <Button
                              onClick={() => removeAsset(index)}
                              size="sm"
                              variant="ghost"
                              className="text-red-400 hover:text-red-300"
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <Button onClick={createCompany} className="w-full bg-blue-600 hover:bg-blue-700">
                    Create Company & Get API Key
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {companies.map((company) => (
          <Card key={company.id} className="bg-slate-900/50 border-slate-800 hover:border-slate-700 transition-colors">
            <CardHeader>
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle className="text-white text-lg">{company.name}</CardTitle>
                  <CardDescription className="text-slate-400 mt-1">
                    {company.assets?.length || 0} assets
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button
                    onClick={() => viewIntegration(company)}
                    size="sm"
                    variant="ghost"
                    className="text-emerald-400 hover:text-emerald-300"
                    title="View Integration"
                  >
                    <Key className="w-4 h-4" />
                  </Button>
                  <Button
                    onClick={() => openEditDialog(company)}
                    size="sm"
                    variant="ghost"
                    className="text-cyan-400 hover:text-cyan-300"
                  >
                    <Edit className="w-4 h-4" />
                  </Button>
                  <Button
                    onClick={() => deleteCompany(company.id, company.name)}
                    size="sm"
                    variant="ghost"
                    className="text-red-400 hover:text-red-300"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-slate-500 mb-1">Maintenance Window</p>
                  <Badge variant="outline" className="bg-slate-800 text-slate-300 border-slate-700">
                    {company.policy?.maintenance_window || 'Not set'}
                  </Badge>
                </div>

                {company.assets && company.assets.length > 0 && (
                  <div>
                    <div className="text-xs text-slate-500 mb-2 flex items-center gap-1">
                      <Server className="w-3 h-3" />
                      <span>Assets</span>
                    </div>
                    <div className="space-y-1">
                      {company.assets.slice(0, 3).map((asset, idx) => (
                        <div key={idx} className="text-xs text-slate-400 flex items-center gap-2">
                          <span className="w-2 h-2 bg-emerald-500 rounded-full"></span>
                          {asset.name} ({asset.type})
                        </div>
                      ))}
                      {company.assets.length > 3 && (
                        <p className="text-xs text-slate-600">+{company.assets.length - 3} more</p>
                      )}
                    </div>
                  </div>
                )}

                {/* KPI Metrics */}
                {companyKPIs[company.id] && (
                  <div className="pt-3 border-t border-slate-800">
                    <p className="text-xs text-slate-500 mb-3">Key Performance Metrics</p>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-slate-800/50 p-2.5 rounded-lg">
                        <p className="text-xs text-slate-500">Noise Reduction</p>
                        <p className={`text-lg font-bold ${companyKPIs[company.id].noise_reduction_pct >= 40 ? 'text-green-400' : 'text-yellow-400'}`}>
                          {companyKPIs[company.id].noise_reduction_pct.toFixed(1)}%
                        </p>
                      </div>
                      <div className="bg-slate-800/50 p-2.5 rounded-lg">
                        <p className="text-xs text-slate-500">MTTR</p>
                        <p className="text-lg font-bold text-cyan-400">
                          {companyKPIs[company.id].mttr_overall_minutes.toFixed(0)}m
                        </p>
                      </div>
                      <div className="bg-slate-800/50 p-2.5 rounded-lg">
                        <p className="text-xs text-slate-500">Self-Healed</p>
                        <p className={`text-lg font-bold ${companyKPIs[company.id].self_healed_pct >= 20 ? 'text-green-400' : 'text-yellow-400'}`}>
                          {companyKPIs[company.id].self_healed_pct.toFixed(1)}%
                        </p>
                      </div>
                      <div className="bg-slate-800/50 p-2.5 rounded-lg">
                        <p className="text-xs text-slate-500">Patch Compliance</p>
                        <p className={`text-lg font-bold ${companyKPIs[company.id].patch_compliance_pct >= 95 ? 'text-green-400' : 'text-yellow-400'}`}>
                          {companyKPIs[company.id].patch_compliance_pct.toFixed(0)}%
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Integration Dialog - Shows API Key and Integration Instructions */}
      <Dialog open={showIntegrationDialog} onOpenChange={setShowIntegrationDialog}>
        <DialogContent className="bg-slate-900 border-slate-800 text-white max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-2xl flex items-center gap-2">
              <Key className="w-6 h-6 text-emerald-400" />
              {newlyCreatedCompany?.name} - Integration Setup
            </DialogTitle>
            <DialogDescription className="text-slate-400">
              Share these details with your client to integrate their monitoring tools
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-6 mt-4">
            {/* Step 1: API Key */}
            <div className="p-5 bg-gradient-to-r from-emerald-500/10 to-cyan-500/10 border border-emerald-500/30 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <span className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500 text-white text-sm font-bold">1</span>
                  API Key
                </h3>
              </div>
              <p className="text-sm text-slate-300 mb-3">This unique key authenticates all alerts from this company</p>
              <div className="flex items-center gap-2 p-3 bg-slate-800/70 rounded border border-slate-700">
                <code className="flex-1 text-emerald-400 font-mono text-sm overflow-x-auto">
                  {newlyCreatedCompany?.api_key || 'No API key available'}
                </code>
                <Button
                  onClick={() => handleCopy(newlyCreatedCompany?.api_key, 'api-key')}
                  size="sm"
                  variant="ghost"
                  className="text-slate-400 hover:text-white"
                >
                  {copiedItem === 'api-key' ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </div>

            {/* Step 2: Webhook URL */}
            <div className="p-5 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <span className="flex items-center justify-center w-6 h-6 rounded-full bg-blue-500 text-white text-sm font-bold">2</span>
                  Webhook Endpoint
                </h3>
              </div>
              <p className="text-sm text-slate-300 mb-3">Configure monitoring tools to send alerts to this URL</p>
              <div className="flex items-center gap-2 p-3 bg-slate-800/70 rounded border border-slate-700">
                <code className="flex-1 text-blue-400 font-mono text-sm overflow-x-auto">
                  {webhookUrl}
                </code>
                <Button
                  onClick={() => handleCopy(webhookUrl, 'webhook-url')}
                  size="sm"
                  variant="ghost"
                  className="text-slate-400 hover:text-white"
                >
                  {copiedItem === 'webhook-url' ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </div>

            {/* Step 3: Example Request */}
            <div className="p-5 bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <span className="flex items-center justify-center w-6 h-6 rounded-full bg-purple-500 text-white text-sm font-bold">3</span>
                  Example Integration
                </h3>
              </div>
              <p className="text-sm text-slate-300 mb-3">Test the integration with this cURL command:</p>
              <div className="relative">
                <pre className="p-4 bg-slate-800/70 border border-slate-700 rounded text-xs overflow-x-auto">
                  <code className="text-purple-300">{`curl -X POST "${webhookUrl}?api_key=${newlyCreatedCompany?.api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "asset_name": "server-01",
    "signature": "high_cpu_usage",
    "severity": "high",
    "message": "CPU usage above 90%",
    "tool_source": "Monitoring System"
  }'`}</code>
                </pre>
                <Button
                  onClick={() => handleCopy(`curl -X POST "${webhookUrl}?api_key=${newlyCreatedCompany?.api_key}" -H "Content-Type: application/json" -d '{"asset_name": "server-01", "signature": "high_cpu_usage", "severity": "high", "message": "CPU usage above 90%", "tool_source": "Monitoring System"}'`, 'curl')}
                  size="sm"
                  variant="ghost"
                  className="absolute top-2 right-2 text-slate-400 hover:text-white"
                >
                  {copiedItem === 'curl' ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </div>

            {/* What Happens Next - Enhanced Automation Flow */}
            <div className="p-5 bg-gradient-to-r from-cyan-500/10 to-teal-500/10 border border-cyan-500/30 rounded-lg">
              <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
                <Send className="w-5 h-5 text-cyan-400" />
                Automated MSP Workflow
              </h3>
              <div className="space-y-3">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-cyan-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                    <span className="text-cyan-400 font-bold text-sm">1</span>
                  </div>
                  <div>
                    <p className="text-white font-medium">Real-Time Alert Reception</p>
                    <p className="text-sm text-slate-400">All alerts sent with this API key are instantly received, validated, and stored with WebSocket broadcasting to connected clients</p>
                  </div>
                </div>
                
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-purple-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                    <span className="text-purple-400 font-bold text-sm">2</span>
                  </div>
                  <div>
                    <p className="text-white font-medium">Event Correlation & Priority Scoring</p>
                    <p className="text-sm text-slate-400">
                      Rule-based algorithms group similar alerts within a configurable time window (5-15 min) by signature and asset. 
                      Priority score calculated: <code className="text-amber-400 text-xs">severity + critical_asset + duplicates + multi_tool - age_decay</code>
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-emerald-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                    <span className="text-emerald-400 font-bold text-sm">3</span>
                  </div>
                  <div>
                    <p className="text-white font-medium">Automated Decision Engine</p>
                    <p className="text-sm text-slate-400">
                      System attempts automated resolution first using predefined playbooks. If successful, incident is self-healed and closed automatically. If not, proceeds to technician assignment.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-orange-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                    <span className="text-orange-400 font-bold text-sm">4</span>
                  </div>
                  <div>
                    <p className="text-white font-medium">Intelligent Technician Assignment</p>
                    <p className="text-sm text-slate-400">
                      For incidents requiring human intervention, system automatically assigns to available technicians based on expertise, workload, and priority. Critical incidents trigger instant notifications.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-pink-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                    <span className="text-pink-400 font-bold text-sm">5</span>
                  </div>
                  <div>
                    <p className="text-white font-medium">Resolution Tracking & Analytics</p>
                    <p className="text-sm text-slate-400">
                      Track MTTR (Mean Time To Resolution), noise reduction %, self-healed incidents, and technician performance. All metrics visible in real-time dashboard.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Security Note */}
            <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg">
              <h4 className="text-amber-400 font-semibold mb-2 text-sm">🔒 Security Best Practices</h4>
              <ul className="text-xs text-amber-200/80 space-y-1">
                <li>• Keep the API key confidential - treat it like a password</li>
                <li>• Share via secure channels (encrypted email, password manager)</li>
                <li>• Regenerate if compromised (click the key icon on company card)</li>
                <li>• Always use HTTPS for API requests</li>
              </ul>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
        <DialogContent className="bg-slate-900 border-slate-800 text-white max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Company</DialogTitle>
            <DialogDescription className="text-slate-400">Update company details</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-4">
            <div>
              <Label>Company Name</Label>
              <Input
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g., Acme Corp"
                className="bg-slate-800 border-slate-700 text-white"
              />
            </div>

            <div>
              <Label>Maintenance Window</Label>
              <Input
                value={formData.policy.maintenance_window}
                onChange={(e) => setFormData({
                  ...formData,
                  policy: { ...formData.policy, maintenance_window: e.target.value }
                })}
                placeholder="e.g., Sat 22:00-02:00"
                className="bg-slate-800 border-slate-700 text-white"
              />
            </div>

            <div className="space-y-2">
              <Label>Assets</Label>
              <div className="grid grid-cols-4 gap-2">
                <Input
                  placeholder="Name"
                  value={assetForm.name}
                  onChange={(e) => setAssetForm({ ...assetForm, name: e.target.value })}
                  className="bg-slate-800 border-slate-700 text-white"
                />
                <Input
                  placeholder="Type"
                  value={assetForm.type}
                  onChange={(e) => setAssetForm({ ...assetForm, type: e.target.value })}
                  className="bg-slate-800 border-slate-700 text-white"
                />
                <Input
                  placeholder="OS"
                  value={assetForm.os}
                  onChange={(e) => setAssetForm({ ...assetForm, os: e.target.value })}
                  className="bg-slate-800 border-slate-700 text-white"
                />
                <Button onClick={addAsset} size="sm" className="bg-cyan-600 hover:bg-cyan-700">
                  <Plus className="w-4 h-4" />
                </Button>
              </div>

              {formData.assets.length > 0 && (
                <div className="mt-2 space-y-1">
                  {formData.assets.map((asset, index) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-slate-800 rounded">
                      <span className="text-sm text-white">{asset.name} - {asset.type} ({asset.os})</span>
                      <Button
                        onClick={() => removeAsset(index)}
                        size="sm"
                        variant="ghost"
                        className="text-red-400 hover:text-red-300"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <Button onClick={updateCompany} className="w-full bg-cyan-600 hover:bg-cyan-700">
              Update Company
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default CompanyManagement;
