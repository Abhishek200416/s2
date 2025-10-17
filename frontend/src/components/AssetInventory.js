import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Server, HardDrive, Cpu, MapPin, Tag, Calendar, CheckCircle,
  XCircle, RefreshCw, Loader, Eye, Search, Filter
} from 'lucide-react';
import { toast } from 'sonner';

const AssetInventory = ({ companyId }) => {
  const [assets, setAssets] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all'); // all, running, stopped
  const [filterSSM, setFilterSSM] = useState('all'); // all, enabled, disabled

  useEffect(() => {
    loadAssets();
  }, [companyId]);

  const loadAssets = async () => {
    setLoading(true);
    try {
      const response = await api.get(`/companies/${companyId}/assets`);
      setAssets(response.data);
    } catch (error) {
      console.error('Failed to load assets:', error);
      toast.error('Failed to load asset inventory');
    } finally {
      setLoading(false);
    }
  };

  const filteredAssets = assets?.assets?.filter(asset => {
    const matchesSearch = 
      asset.instance_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.instance_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (asset.private_ip && asset.private_ip.includes(searchTerm)) ||
      (asset.public_ip && asset.public_ip.includes(searchTerm));
    
    const matchesStatus = filterStatus === 'all' || asset.state === filterStatus;
    
    const matchesSSM = 
      filterSSM === 'all' ||
      (filterSSM === 'enabled' && asset.ssm_agent_installed) ||
      (filterSSM === 'disabled' && !asset.ssm_agent_installed);
    
    return matchesSearch && matchesStatus && matchesSSM;
  }) || [];

  const getStateBadge = (state) => {
    const badges = {
      'running': { color: 'bg-green-500/20 text-green-400 border-green-500/30', icon: CheckCircle },
      'stopped': { color: 'bg-red-500/20 text-red-400 border-red-500/30', icon: XCircle },
      'pending': { color: 'bg-amber-500/20 text-amber-400 border-amber-500/30', icon: Loader },
      'stopping': { color: 'bg-amber-500/20 text-amber-400 border-amber-500/30', icon: Loader },
      'terminated': { color: 'bg-slate-500/20 text-slate-400 border-slate-500/30', icon: XCircle }
    };
    
    const badge = badges[state] || badges['stopped'];
    const Icon = badge.icon;
    
    return (
      <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold border ${badge.color}`}>
        <Icon className="w-3 h-3" />
        {state.charAt(0).toUpperCase() + state.slice(1)}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader className="w-8 h-8 text-cyan-400 animate-spin mr-3" />
        <span className="text-slate-400">Loading asset inventory...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Asset Inventory</h2>
          <p className="text-slate-400">
            EC2 instances for {assets?.company_name}
          </p>
        </div>
        <Button
          onClick={loadAssets}
          variant="outline"
          className="border-slate-700 text-slate-300"
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <Server className="w-8 h-8 text-cyan-400" />
              <div className="text-3xl font-bold text-white">
                {assets?.total_assets || 0}
              </div>
            </div>
            <div className="text-sm text-slate-400">Total Instances</div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-green-500/30">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <CheckCircle className="w-8 h-8 text-green-400" />
              <div className="text-3xl font-bold text-green-400">
                {assets?.ssm_enabled_assets || 0}
              </div>
            </div>
            <div className="text-sm text-green-300">SSM Agent Installed</div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border-cyan-500/30">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <CheckCircle className="w-8 h-8 text-cyan-400" />
              <div className="text-3xl font-bold text-cyan-400">
                {assets?.ssm_online_assets || 0}
              </div>
            </div>
            <div className="text-sm text-cyan-300">SSM Online</div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <HardDrive className="w-8 h-8 text-purple-400" />
              <div className="text-3xl font-bold text-white">
                {filteredAssets.filter(a => a.state === 'running').length}
              </div>
            </div>
            <div className="text-sm text-slate-400">Running</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardContent className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
              <input
                type="text"
                placeholder="Search instances..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>

            {/* Status Filter */}
            <div>
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <option value="all">All States</option>
                <option value="running">Running</option>
                <option value="stopped">Stopped</option>
                <option value="pending">Pending</option>
                <option value="terminated">Terminated</option>
              </select>
            </div>

            {/* SSM Filter */}
            <div>
              <select
                value={filterSSM}
                onChange={(e) => setFilterSSM(e.target.value)}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <option value="all">All SSM Status</option>
                <option value="enabled">SSM Enabled</option>
                <option value="disabled">SSM Disabled</option>
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Assets List */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Instances ({filteredAssets.length})</CardTitle>
          <CardDescription className="text-slate-400">
            Detailed information for all EC2 instances
          </CardDescription>
        </CardHeader>
        <CardContent>
          {filteredAssets.length > 0 ? (
            <div className="space-y-3">
              {filteredAssets.map((asset) => (
                <div
                  key={asset.instance_id}
                  className="p-5 bg-slate-800/50 border border-slate-700 rounded-lg hover:border-slate-600 transition-colors"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${
                        asset.ssm_agent_online
                          ? 'bg-green-500/20 text-green-400'
                          : asset.ssm_agent_installed
                            ? 'bg-amber-500/20 text-amber-400'
                            : 'bg-slate-500/20 text-slate-400'
                      }`}>
                        <Server className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <span className="text-lg font-semibold text-white">
                            {asset.instance_name}
                          </span>
                          {getStateBadge(asset.state)}
                        </div>
                        <div className="font-mono text-sm text-slate-400">
                          {asset.instance_id}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      {asset.ssm_agent_installed ? (
                        <div className="flex items-center gap-2 text-sm">
                          <CheckCircle className={`w-4 h-4 ${
                            asset.ssm_agent_online ? 'text-green-400' : 'text-amber-400'
                          }`} />
                          <span className={
                            asset.ssm_agent_online ? 'text-green-400' : 'text-amber-400'
                          }>
                            SSM {asset.ssm_agent_online ? 'Online' : 'Offline'}
                          </span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2 text-sm text-slate-500">
                          <XCircle className="w-4 h-4" />
                          No SSM Agent
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Details Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div>
                      <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                        <Cpu className="w-3 h-3" />
                        Instance Type
                      </div>
                      <div className="text-sm text-slate-300 font-medium">
                        {asset.instance_type}
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                        <Server className="w-3 h-3" />
                        Platform
                      </div>
                      <div className="text-sm text-slate-300">
                        {asset.ssm_platform || asset.platform}
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                        <Server className="w-3 h-3" />
                        Private IP
                      </div>
                      <div className="text-sm text-slate-300 font-mono">
                        {asset.private_ip || 'N/A'}
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                        <Server className="w-3 h-3" />
                        Public IP
                      </div>
                      <div className="text-sm text-slate-300 font-mono">
                        {asset.public_ip || 'N/A'}
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div>
                      <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                        <MapPin className="w-3 h-3" />
                        Availability Zone
                      </div>
                      <div className="text-sm text-slate-300">
                        {asset.availability_zone}
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                        <Calendar className="w-3 h-3" />
                        Launch Time
                      </div>
                      <div className="text-sm text-slate-300">
                        {asset.launch_time 
                          ? new Date(asset.launch_time).toLocaleDateString()
                          : 'N/A'}
                      </div>
                    </div>
                    {asset.ssm_agent_version && (
                      <div>
                        <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                          <CheckCircle className="w-3 h-3" />
                          SSM Version
                        </div>
                        <div className="text-sm text-slate-300 font-mono">
                          {asset.ssm_agent_version}
                        </div>
                      </div>
                    )}
                    {asset.ssm_last_ping && (
                      <div>
                        <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                          <CheckCircle className="w-3 h-3" />
                          Last SSM Ping
                        </div>
                        <div className="text-sm text-slate-300">
                          {new Date(asset.ssm_last_ping).toLocaleString()}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Tags */}
                  {Object.keys(asset.tags).length > 0 && (
                    <div>
                      <div className="flex items-center gap-2 text-xs text-slate-500 mb-2">
                        <Tag className="w-3 h-3" />
                        Tags
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(asset.tags).map(([key, value]) => (
                          <div 
                            key={key}
                            className="px-2 py-1 bg-slate-700/50 border border-slate-600 rounded text-xs"
                          >
                            <span className="text-slate-400">{key}:</span>
                            <span className="text-slate-300 ml-1">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Server className="w-16 h-16 text-slate-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-slate-400 mb-2">
                No Instances Found
              </h3>
              <p className="text-slate-500">
                {searchTerm || filterStatus !== 'all' || filterSSM !== 'all'
                  ? 'No instances match your filters'
                  : 'No EC2 instances found for this company'}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default AssetInventory;
