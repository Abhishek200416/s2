import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Search, Play, Code, Shield, HardDrive, Server, 
  Database, Cpu, Network, FileText, AlertCircle,
  CheckCircle, Loader, ArrowLeft
} from 'lucide-react';
import { toast } from 'sonner';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';

/**
 * Runbook Library - Browse and execute pre-built MSP runbooks
 */
const RunbookLibrary = () => {
  const navigate = useNavigate();
  const [library, setLibrary] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedRunbook, setSelectedRunbook] = useState(null);
  const [showExecuteDialog, setShowExecuteDialog] = useState(false);
  const [instanceId, setInstanceId] = useState('');
  const [executing, setExecuting] = useState(false);
  const [companies, setCompanies] = useState([]);
  const [selectedCompany, setSelectedCompany] = useState('');

  const categoryIcons = {
    disk: HardDrive,
    application: Server,
    database: Database,
    memory: Cpu,
    cpu: Cpu,
    network: Network,
    security: Shield,
    monitoring: AlertCircle
  };

  const riskColors = {
    low: 'green',
    medium: 'amber',
    high: 'red'
  };

  useEffect(() => {
    loadLibrary();
    loadCompanies();
  }, []);

  const loadLibrary = async () => {
    try {
      const response = await api.get('/runbooks/global-library');
      setLibrary(response.data);
    } catch (error) {
      console.error('Failed to load runbook library:', error);
      toast.error('Failed to load runbook library');
    }
  };

  const loadCompanies = async () => {
    try {
      const response = await api.get('/companies');
      setCompanies(response.data);
      if (response.data.length > 0) {
        setSelectedCompany(response.data[0].id);
      }
    } catch (error) {
      console.error('Failed to load companies:', error);
    }
  };

  const filteredRunbooks = library?.runbooks.filter(runbook => {
    const matchesSearch = runbook.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         runbook.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || runbook.category === selectedCategory;
    return matchesSearch && matchesCategory;
  }) || [];

  const handleExecute = (runbook) => {
    setSelectedRunbook(runbook);
    setShowExecuteDialog(true);
  };

  const executeRunbook = async () => {
    if (!instanceId.trim()) {
      toast.error('Please enter an instance ID');
      return;
    }

    if (!selectedCompany) {
      toast.error('Please select a company');
      return;
    }

    setExecuting(true);
    try {
      // Create a temporary runbook in the database
      const createResponse = await api.post('/runbooks', {
        name: selectedRunbook.name,
        description: selectedRunbook.description,
        risk_level: selectedRunbook.risk_level,
        signature: selectedRunbook.name.toLowerCase().replace(/\s+/g, '_'),
        actions: [selectedRunbook.script_content],
        auto_approve: selectedRunbook.auto_approve,
        company_id: selectedCompany
      });

      const runbookId = createResponse.data.id;

      // Execute via SSM
      const executeResponse = await api.post('/runbooks/execute-ssm', {
        runbook_id: runbookId,
        instance_ids: [instanceId],
        company_id: selectedCompany
      });

      toast.success(`Runbook execution started! Command ID: ${executeResponse.data.command_id}`);
      setShowExecuteDialog(false);
      setInstanceId('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to execute runbook');
    } finally {
      setExecuting(false);
    }
  };

  if (!library) {
    return (
      <div className="flex items-center justify-center h-screen">
        <Loader className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header with Navigation */}
      <div className="bg-slate-800 border-b border-slate-700 p-4">
        <div className="max-w-7xl mx-auto">
          <Button
            onClick={() => navigate('/dashboard')}
            variant="ghost"
            size="sm"
            className="text-slate-400 hover:bg-slate-800 mb-3"
            style={{ '--hover-color': 'hsl(var(--card-foreground))' }}
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Button>
          <h1 className="text-3xl font-bold mb-2" style={{ color: 'hsl(var(--card-foreground))' }}>📚 Runbook Library</h1>
          <p className="text-slate-400">
            Pre-built automation scripts for common MSP tasks. {library.total_count} runbooks available.
          </p>
        </div>
      </div>

      <div className="p-6 space-y-6 max-w-7xl mx-auto">

      {/* Search and Filter */}
      <div className="flex items-center gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-5 h-5" />
          <Input
            placeholder="Search runbooks..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 bg-slate-800 border-slate-700"
            style={{ color: 'hsl(var(--card-foreground))' }}
          />
        </div>
      </div>

      {/* Category Tabs */}
      <Tabs value={selectedCategory} onValueChange={setSelectedCategory}>
        <TabsList className="bg-slate-800 border-slate-700">
          <TabsTrigger value="all" className="data-[state=active]:bg-purple-600">
            All ({library.total_count})
          </TabsTrigger>
          {library.category_list.map(category => {
            const Icon = categoryIcons[category] || FileText;
            const count = library.categories[category]?.length || 0;
            return (
              <TabsTrigger 
                key={category} 
                value={category}
                className="data-[state=active]:bg-purple-600"
              >
                <Icon className="w-4 h-4 mr-2" />
                {category.charAt(0).toUpperCase() + category.slice(1)} ({count})
              </TabsTrigger>
            );
          })}
        </TabsList>

        <TabsContent value={selectedCategory} className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredRunbooks.map((runbook, index) => {
              const Icon = categoryIcons[runbook.category] || FileText;
              const riskColor = riskColors[runbook.risk_level] || 'slate';
              
              return (
                <Card key={index} className="bg-slate-900/90 border-slate-700/50 hover:border-purple-500 transition-all">
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
                        {runbook.script_type}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {runbook.cloud_provider}
                      </Badge>
                      {runbook.auto_approve && (
                        <Badge variant="outline" className="text-xs bg-green-500/10 text-green-400">
                          <CheckCircle className="w-3 h-3 mr-1" />
                          Auto
                        </Badge>
                      )}
                    </div>

                    {runbook.tags && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {runbook.tags.slice(0, 3).map((tag, i) => (
                          <span key={i} className="text-xs px-2 py-0.5 rounded bg-slate-700 text-slate-300">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}

                    <Button
                      size="sm"
                      onClick={() => handleExecute(runbook)}
                      className="w-full bg-purple-600 hover:bg-purple-700"
                    >
                      <Play className="w-4 h-4 mr-2" />
                      Execute
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {filteredRunbooks.length === 0 && (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <p className="text-slate-400">No runbooks found matching your search.</p>
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Execute Dialog */}
      <Dialog open={showExecuteDialog} onOpenChange={setShowExecuteDialog}>
        <DialogContent className="bg-slate-900/95 border-slate-700/50 max-w-2xl">
          <DialogHeader>
            <DialogTitle style={{ color: 'hsl(var(--card-foreground))' }} className="flex items-center gap-2">
              <Play className="w-5 h-5 text-cyan-400" />
              Execute Runbook
            </DialogTitle>
            <DialogDescription>
              {selectedRunbook?.name}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {/* Company Selection */}
            <div>
              <label className="text-sm font-medium mb-2 block" style={{ color: 'hsl(var(--card-foreground))' }}>Company</label>
              <select
                value={selectedCompany}
                onChange={(e) => setSelectedCompany(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2"
                style={{ color: 'hsl(var(--card-foreground))' }}
              >
                {companies.map(company => (
                  <option key={company.id} value={company.id}>
                    {company.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Instance ID */}
            <div>
              <label className="text-sm font-medium mb-2 block" style={{ color: 'hsl(var(--card-foreground))' }}>EC2 Instance ID</label>
              <Input
                placeholder="e.g., i-1234567890abcdef0"
                value={instanceId}
                onChange={(e) => setInstanceId(e.target.value)}
                className="bg-slate-900 border-slate-700"
                style={{ color: 'hsl(var(--card-foreground))' }}
              />
              <p className="text-slate-400 text-xs mt-1">
                The instance must have SSM agent installed and running
              </p>
            </div>

            {/* Risk Warning */}
            {selectedRunbook && selectedRunbook.risk_level !== 'low' && (
              <div className={`bg-amber-900/20 border border-amber-500/30 rounded-lg p-3`}>
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-5 h-5 text-amber-400 mt-0.5" />
                  <div>
                    <p className="text-amber-300 text-sm font-medium">
                      {selectedRunbook.risk_level.charAt(0).toUpperCase() + selectedRunbook.risk_level.slice(1)} Risk Runbook
                    </p>
                    <p className="text-slate-400 text-xs mt-1">
                      {selectedRunbook.auto_approve 
                        ? 'This runbook will execute immediately without approval.' 
                        : 'This runbook requires approval before execution.'}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Script Preview */}
            <div>
              <label className="text-sm font-medium mb-2 block flex items-center gap-2" style={{ color: 'hsl(var(--card-foreground))' }}>
                <Code className="w-4 h-4" />
                Script Preview
              </label>
              <pre className="bg-black text-green-400 p-3 rounded-lg overflow-x-auto text-xs max-h-40">
                <code>{selectedRunbook?.script_content}</code>
              </pre>
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-3 pt-4">
              <Button
                variant="outline"
                onClick={() => setShowExecuteDialog(false)}
                disabled={executing}
                className="border-slate-600"
              >
                Cancel
              </Button>
              <Button
                onClick={executeRunbook}
                disabled={executing || !instanceId.trim()}
                className="bg-purple-600 hover:bg-purple-700"
              >
                {executing ? (
                  <>
                    <Loader className="w-4 h-4 mr-2 animate-spin" />
                    Executing...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" />
                    Execute Now
                  </>
                )}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
    </div>
  );
};

export default RunbookLibrary;
