import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Server, HardDrive, Cpu, MapPin, Tag, Calendar, CheckCircle,
  XCircle, RefreshCw, Loader, Eye, Search, Filter
} from 'lucide-react';
import { toast } from 'sonner';

const AssetInventory = ({ companyId, refreshTrigger }) => {
  const [assets, setAssets] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadAssets();
  }, [companyId, refreshTrigger]);

  const loadAssets = async () => {
    setLoading(true);
    try {
      // Load company data which includes the assets array
      const response = await api.get(`/companies/${companyId}`);
      const companyData = response.data;
      
      // Set assets from company data
      setAssets({
        company_name: companyData.name,
        assets: companyData.assets || [],
        total_assets: (companyData.assets || []).length
      });
    } catch (error) {
      console.error('Failed to load assets:', error);
      toast.error('Failed to load asset inventory');
    } finally {
      setLoading(false);
    }
  };

  const filteredAssets = assets?.assets?.filter(asset => {
    const matchesSearch = 
      (asset.name && asset.name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (asset.id && asset.id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (asset.type && asset.type.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (asset.os && asset.os.toLowerCase().includes(searchTerm.toLowerCase()));
    
    // Since these are company assets not EC2, we don't have state/SSM filters
    return matchesSearch;
  }) || [];

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
            Configured assets for {assets?.company_name}
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
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <Server className="w-8 h-8 text-cyan-400" />
              <div className="text-3xl font-bold text-white">
                {assets?.total_assets || 0}
              </div>
            </div>
            <div className="text-sm text-slate-400">Total Assets</div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-500/10 to-red-500/10 border-orange-500/30">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <Tag className="w-8 h-8 text-orange-400" />
              <div className="text-3xl font-bold text-orange-400">
                {filteredAssets.filter(a => a.is_critical).length}
              </div>
            </div>
            <div className="text-sm text-orange-300">Critical Assets</div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-purple-500/30">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <HardDrive className="w-8 h-8 text-purple-400" />
              <div className="text-3xl font-bold text-purple-400">
                {new Set(filteredAssets.map(a => a.type)).size}
              </div>
            </div>
            <div className="text-sm text-purple-300">Asset Types</div>
          </CardContent>
        </Card>
      </div>

      {/* Search Filter */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardContent className="p-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
            <input
              type="text"
              placeholder="Search assets by name, type, or OS..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </CardContent>
      </Card>

      {/* Assets List */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Assets ({filteredAssets.length})</CardTitle>
          <CardDescription className="text-slate-400">
            All configured assets for this company
          </CardDescription>
        </CardHeader>
        <CardContent>
          {filteredAssets.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredAssets.map((asset) => (
                <div
                  key={asset.id}
                  className="p-5 bg-slate-800/50 border border-slate-700 rounded-lg hover:border-slate-600 transition-colors"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${
                        asset.is_critical
                          ? 'bg-orange-500/20 text-orange-400'
                          : 'bg-cyan-500/20 text-cyan-400'
                      }`}>
                        <Server className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="text-lg font-semibold text-white mb-1">
                          {asset.name}
                        </div>
                        <div className="text-xs text-slate-400">
                          {asset.id}
                        </div>
                      </div>
                    </div>
                    {asset.is_critical && (
                      <Tag className="w-5 h-5 text-orange-400" title="Critical Asset" />
                    )}
                  </div>

                  {/* Details */}
                  <div className="space-y-2 mt-4">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-slate-400">Type</span>
                      <span className="text-white font-medium">{asset.type}</span>
                    </div>
                    {asset.os && (
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">OS</span>
                        <span className="text-white font-medium">{asset.os}</span>
                      </div>
                    )}
                    {asset.tags && asset.tags.length > 0 && (
                      <div className="flex items-start justify-between text-sm">
                        <span className="text-slate-400">Tags</span>
                        <div className="flex flex-wrap gap-1 justify-end">
                          {asset.tags.slice(0, 3).map((tag, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-0.5 bg-slate-700 text-slate-300 text-xs rounded"
                            >
                              {tag}
                            </span>
                          ))}
                          {asset.tags.length > 3 && (
                            <span className="px-2 py-0.5 bg-slate-700 text-slate-300 text-xs rounded">
                              +{asset.tags.length - 3}
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Server className="w-16 h-16 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-400 text-lg">No assets found</p>
              <p className="text-slate-500 text-sm mt-2">
                {searchTerm ? 'Try adjusting your search' : 'Add assets in the Companies section'}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default AssetInventory;
