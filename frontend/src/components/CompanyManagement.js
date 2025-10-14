import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Building2, Plus, Edit, Trash2, Server } from 'lucide-react';
import { toast } from 'sonner';

const CompanyManagement = ({ onCompanyChange }) => {
  const [companies, setCompanies] = useState([]);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [selectedCompany, setSelectedCompany] = useState(null);
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
    } catch (error) {
      console.error('Failed to load companies:', error);
    }
  };

  const createCompany = async () => {
    try {
      await api.post('/companies', formData);
      toast.success('Company created successfully');
      setShowCreateDialog(false);
      resetForm();
      await loadCompanies();
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

                  <Button onClick={createCompany} className="w-full bg-blue-600 hover:bg-blue-700">
                    Create Company
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
                    <p className="text-xs text-slate-500 mb-2 flex items-center gap-1">
                      <Server className="w-3 h-3" />
                      Assets
                    </p>
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
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Edit Dialog */}
      <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
        <DialogContent className="bg-slate-900 border-slate-800 text-white max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Company</DialogTitle>
            <DialogDescription className="text-slate-400">Update company information</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-4">
            <div>
              <Label>Company Name</Label>
              <Input
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="bg-slate-800 border-slate-700 text-white"
              />
            </div>

            <div>
              <Label>Maintenance Window</Label>
              <Input
                value={formData.policy?.maintenance_window || ''}
                onChange={(e) => setFormData({
                  ...formData,
                  policy: { ...formData.policy, maintenance_window: e.target.value }
                })}
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

              {formData.assets && formData.assets.length > 0 && (
                <div className="mt-2 space-y-1 max-h-40 overflow-y-auto">
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

            <Button onClick={updateCompany} className="w-full bg-blue-600 hover:bg-blue-700">
              Update Company
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default CompanyManagement;