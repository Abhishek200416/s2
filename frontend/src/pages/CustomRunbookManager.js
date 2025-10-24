import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  Plus, Edit2, Trash2, Save, X, Code, Shield, 
  HardDrive, Server, Database, Cpu, Network, AlertCircle,
  FileText, Search
} from 'lucide-react';
import { toast } from 'sonner';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';

/**
 * Custom Runbook Manager - Create, edit, and manage your own runbooks
 */
const CustomRunbookManager = ({ companyId, refreshTrigger }) => {
  const [runbooks, setRunbooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showDialog, setShowDialog] = useState(false);
  const [editingRunbook, setEditingRunbook] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    category: 'application',
    risk_level: 'low',
    script_content: '',
    script_type: 'shell',
    auto_approve: true
  });

  const categories = [
    { value: 'disk', label: 'Disk Management', icon: HardDrive },
    { value: 'application', label: 'Application', icon: Server },
    { value: 'database', label: 'Database', icon: Database },
    { value: 'memory', label: 'Memory', icon: Cpu },
    { value: 'cpu', label: 'CPU', icon: Cpu },
    { value: 'network', label: 'Network', icon: Network },
    { value: 'security', label: 'Security', icon: Shield },
    { value: 'monitoring', label: 'Monitoring', icon: AlertCircle }
  ];

  const riskLevels = [
    { value: 'low', label: 'Low Risk', color: 'green', description: 'Auto-approved, minimal impact' },
    { value: 'medium', label: 'Medium Risk', color: 'amber', description: 'Requires approval from Company/MSP Admin' },
    { value: 'high', label: 'High Risk', color: 'red', description: 'Requires MSP Admin approval only' }
  ];

  const scriptTypes = [
    { value: 'shell', label: 'Shell Script (bash)' },
    { value: 'powershell', label: 'PowerShell' },
    { value: 'python', label: 'Python' },
    { value: 'ssm-document', label: 'AWS SSM Document' }
  ];

  useEffect(() => {
    if (companyId) {
      loadRunbooks();
    }
  }, [companyId, refreshTrigger]);

  const loadRunbooks = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/runbooks?company_id=${companyId}`);
      setRunbooks(response.data || []);
    } catch (error) {
      console.error('Failed to load runbooks:', error);
      toast.error('Failed to load custom runbooks');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    setEditingRunbook(null);
    setFormData({
      name: '',
      description: '',
      category: 'application',
      risk_level: 'low',
      script_content: '',
      script_type: 'shell',
      auto_approve: true
    });
    setShowDialog(true);
  };

  const handleEdit = (runbook) => {
    setEditingRunbook(runbook);
    setFormData({
      name: runbook.name,
      description: runbook.description,
      category: runbook.category || 'application',
      risk_level: runbook.risk_level,
      script_content: runbook.actions?.[0] || '',
      script_type: runbook.script_type || 'shell',
      auto_approve: runbook.auto_approve
    });
    setShowDialog(true);
  };

  const handleSave = async () => {
    if (!formData.name.trim()) {
      toast.error('Runbook name is required');
      return;
    }
    if (!formData.script_content.trim()) {
      toast.error('Script content is required');
      return;
    }

    try {
      const payload = {
        name: formData.name,
        description: formData.description,
        risk_level: formData.risk_level,
        signature: formData.name.toLowerCase().replace(/\s+/g, '_'),
        actions: [formData.script_content],
        auto_approve: formData.auto_approve,
        company_id: companyId,
        category: formData.category,
        script_type: formData.script_type
      };

      if (editingRunbook) {
        await api.put(`/runbooks/${editingRunbook.id}`, payload);
        toast.success('Runbook updated successfully');
      } else {
        await api.post('/runbooks', payload);
        toast.success('Runbook created successfully');
      }

      setShowDialog(false);
      loadRunbooks();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to save runbook');
    }
  };

  const handleDelete = async (runbookId) => {
    if (!window.confirm('Are you sure you want to delete this runbook? This action cannot be undone.')) {
      return;
    }

    try {
      await api.delete(`/runbooks/${runbookId}`);
      toast.success('Runbook deleted successfully');
      loadRunbooks();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to delete runbook');
    }
  };

  const filteredRunbooks = runbooks.filter(runbook =>
    runbook.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    runbook.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getCategoryIcon = (category) => {
    const cat = categories.find(c => c.value === category);
    return cat ? cat.icon : FileText;
  };

  const getRiskColor = (risk) => {
    const level = riskLevels.find(r => r.value === risk);
    return level ? level.color : 'slate';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-slate-400">Loading custom runbooks...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold mb-2" style={{ color: 'hsl(var(--card-foreground))' }}>Custom Runbooks</h2>
          <p className="text-slate-400">
            Create and manage your own custom automation scripts for your infrastructure
          </p>
        </div>
        <Button
          onClick={handleCreate}
          className="bg-cyan-600 hover:bg-cyan-700"
        >
          <Plus className="w-4 h-4 mr-2" />
          Create Runbook
        </Button>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-5 h-5" />
        <Input
          placeholder="Search custom runbooks..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="pl-10 bg-slate-800 border-slate-700 text-white"
        />
      </div>

      {/* Runbooks Grid */}
      {filteredRunbooks.length === 0 ? (
        <Card className="bg-slate-900/90 border-slate-700/50">
          <CardContent className="py-12 text-center">
            <FileText className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 mb-4">
              {searchTerm ? 'No runbooks found matching your search.' : 'No custom runbooks yet. Create your first one!'}
            </p>
            {!searchTerm && (
              <Button
                onClick={handleCreate}
                className="bg-cyan-600 hover:bg-cyan-700"
              >
                <Plus className="w-4 h-4 mr-2" />
                Create Your First Runbook
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredRunbooks.map((runbook) => {
            const Icon = getCategoryIcon(runbook.category);
            const riskColor = getRiskColor(runbook.risk_level);
            
            return (
              <Card key={runbook.id} className="bg-slate-900/90 border-slate-700/50 hover:border-purple-500 transition-all">
                <CardHeader>
                  <div className="flex items-start justify-between mb-2">
                    <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                      <Icon className="w-5 h-5 text-purple-400" />
                    </div>
                    <Badge className={`bg-${riskColor}-500/20 text-${riskColor}-400 border-${riskColor}-500/30`}>
                      {runbook.risk_level}
                    </Badge>
                  </div>
                  <CardTitle className="text-lg" style={{ color: 'hsl(var(--card-foreground))' }}>{runbook.name}</CardTitle>
                  <CardDescription className="text-sm" style={{ color: 'hsl(var(--muted-foreground))' }}>
                    {runbook.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-2 mb-3">
                    <Badge variant="outline" className="text-xs">
                      {runbook.script_type || 'shell'}
                    </Badge>
                    <Badge variant="outline" className="text-xs">
                      {runbook.category || 'general'}
                    </Badge>
                  </div>

                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleEdit(runbook)}
                      className="flex-1 border-slate-600 hover:bg-slate-700"
                    >
                      <Edit2 className="w-3 h-3 mr-1" />
                      Edit
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleDelete(runbook.id)}
                      className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                    >
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={showDialog} onOpenChange={setShowDialog}>
        <DialogContent className="bg-slate-800 border-slate-700 max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-white flex items-center gap-2">
              <Code className="w-5 h-5 text-cyan-400" />
              {editingRunbook ? 'Edit Runbook' : 'Create Custom Runbook'}
            </DialogTitle>
            <DialogDescription>
              {editingRunbook ? 'Update your custom runbook details' : 'Create a new custom automation script'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {/* Name */}
            <div>
              <label className="text-white text-sm font-medium mb-2 block">Runbook Name *</label>
              <Input
                placeholder="e.g., Restart Application Server"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="bg-slate-900 border-slate-700 text-white"
              />
            </div>

            {/* Description */}
            <div>
              <label className="text-white text-sm font-medium mb-2 block">Description *</label>
              <textarea
                placeholder="Describe what this runbook does..."
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                rows={3}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white resize-none"
              />
            </div>

            {/* Category and Script Type */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-white text-sm font-medium mb-2 block">Category *</label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
                >
                  {categories.map(cat => (
                    <option key={cat.value} value={cat.value}>{cat.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-white text-sm font-medium mb-2 block">Script Type *</label>
                <select
                  value={formData.script_type}
                  onChange={(e) => setFormData({ ...formData, script_type: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white"
                >
                  {scriptTypes.map(type => (
                    <option key={type.value} value={type.value}>{type.label}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Risk Level */}
            <div>
              <label className="text-white text-sm font-medium mb-2 block">Risk Level *</label>
              <div className="grid grid-cols-3 gap-3">
                {riskLevels.map(risk => (
                  <div
                    key={risk.value}
                    onClick={() => setFormData({ 
                      ...formData, 
                      risk_level: risk.value,
                      auto_approve: risk.value === 'low'
                    })}
                    className={`
                      p-3 rounded-lg border-2 cursor-pointer transition-all
                      ${formData.risk_level === risk.value
                        ? `border-${risk.color}-500 bg-${risk.color}-500/10`
                        : 'border-slate-700 bg-slate-900 hover:border-slate-600'
                      }
                    `}
                  >
                    <p className={`font-medium text-${risk.color}-400 text-sm mb-1`}>
                      {risk.label}
                    </p>
                    <p className="text-slate-400 text-xs">
                      {risk.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* Script Content */}
            <div>
              <label className="text-white text-sm font-medium mb-2 block flex items-center gap-2">
                <Code className="w-4 h-4" />
                Script Content *
              </label>
              <textarea
                placeholder={`# Enter your ${formData.script_type} script here...\n# Example:\necho "Starting maintenance..."\nsudo systemctl restart application\necho "Maintenance complete"`}
                value={formData.script_content}
                onChange={(e) => setFormData({ ...formData, script_content: e.target.value })}
                rows={12}
                className="w-full bg-black text-green-400 border border-slate-700 rounded-lg px-3 py-2 font-mono text-sm resize-none"
              />
              <p className="text-slate-400 text-xs mt-1">
                This script will be executed on target instances via AWS SSM
              </p>
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-3 pt-4 border-t border-slate-700">
              <Button
                variant="outline"
                onClick={() => setShowDialog(false)}
                className="border-slate-600"
              >
                <X className="w-4 h-4 mr-2" />
                Cancel
              </Button>
              <Button
                onClick={handleSave}
                className="bg-cyan-600 hover:bg-cyan-700"
              >
                <Save className="w-4 h-4 mr-2" />
                {editingRunbook ? 'Update Runbook' : 'Create Runbook'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default CustomRunbookManager;
