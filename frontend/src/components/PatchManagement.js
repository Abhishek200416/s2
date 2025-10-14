import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Database, Play, CheckCircle, ArrowRight, Clock } from 'lucide-react';
import { toast } from 'sonner';

const PatchManagement = ({ companyId }) => {
  const [patches, setPatches] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (companyId) {
      loadPatches();
    }
  }, [companyId]);

  const loadPatches = async () => {
    try {
      const response = await api.get(`/patches?company_id=${companyId}`);
      setPatches(response.data);
    } catch (error) {
      console.error('Failed to load patches:', error);
    }
  };

  const startCanary = async (patchId) => {
    setLoading(true);
    try {
      await api.post(`/patches/${patchId}/canary`);
      toast.success('Canary deployment started');
      await loadPatches();
    } catch (error) {
      console.error('Failed to start canary:', error);
      toast.error('Failed to start canary');
    } finally {
      setLoading(false);
    }
  };

  const rolloutPatch = async (patchId) => {
    setLoading(true);
    try {
      await api.post(`/patches/${patchId}/rollout`);
      toast.success('Patch rollout initiated');
      await loadPatches();
    } catch (error) {
      console.error('Failed to rollout patch:', error);
      toast.error('Failed to rollout patch');
    } finally {
      setLoading(false);
    }
  };

  const completePatch = async (patchId) => {
    setLoading(true);
    try {
      await api.post(`/patches/${patchId}/complete`);
      toast.success('Patch deployment complete');
      await loadPatches();
    } catch (error) {
      console.error('Failed to complete patch:', error);
      toast.error('Failed to complete patch');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      proposed: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      canary_in_progress: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      canary_complete: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
      rolling_out: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      complete: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      failed: 'bg-red-500/20 text-red-300 border-red-500/30'
    };
    return colors[status] || colors.proposed;
  };

  const getSeverityColor = (severity) => {
    const colors = {
      low: 'bg-slate-500/20 text-slate-300',
      medium: 'bg-amber-500/20 text-amber-300',
      high: 'bg-orange-500/20 text-orange-300',
      critical: 'bg-red-500/20 text-red-300'
    };
    return colors[severity] || colors.low;
  };

  return (
    <div className="space-y-6" data-testid="patch-management">
      {/* Header */}
      <Card className="bg-gradient-to-br from-purple-500/10 to-blue-500/10 border-purple-500/30">
        <CardHeader>
          <CardTitle className="text-white text-2xl flex items-center gap-3">
            <Database className="w-6 h-6 text-purple-400" />
            Patch Management
          </CardTitle>
          <CardDescription className="text-slate-300">
            Safe canary deployment with verification and rollback capabilities
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-blue-500"></div>
              <span className="text-slate-400">Proposed</span>
            </div>
            <ArrowRight className="w-4 h-4 text-slate-600" />
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-amber-500"></div>
              <span className="text-slate-400">Canary</span>
            </div>
            <ArrowRight className="w-4 h-4 text-slate-600" />
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-cyan-500"></div>
              <span className="text-slate-400">Verify</span>
            </div>
            <ArrowRight className="w-4 h-4 text-slate-600" />
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-purple-500"></div>
              <span className="text-slate-400">Rollout</span>
            </div>
            <ArrowRight className="w-4 h-4 text-slate-600" />
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
              <span className="text-slate-400">Complete</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Patch Plans */}
      {patches.length === 0 ? (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="py-12 text-center">
            <Database className="w-12 h-12 mx-auto mb-4 text-slate-600" />
            <p className="text-slate-400">No patch plans found for this company</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {patches.map((patch) => (
            <Card key={patch.id} className="bg-slate-900/50 border-slate-800" data-testid={`patch-plan-${patch.id}`}>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="text-white text-lg flex items-center gap-2 mb-2">
                      Patch Plan #{patch.id.slice(-8)}
                      <Badge className={`${getStatusColor(patch.status)} border`}>
                        {patch.status.replace(/_/g, ' ')}
                      </Badge>
                    </CardTitle>
                    <CardDescription className="text-slate-400">
                      Maintenance Window: {patch.window}
                    </CardDescription>
                  </div>
                  <div className="flex gap-2">
                    {patch.status === 'proposed' && (
                      <Button
                        onClick={() => startCanary(patch.id)}
                        disabled={loading}
                        size="sm"
                        className="bg-amber-600 hover:bg-amber-700 text-white"
                        data-testid={`start-canary-${patch.id}`}
                      >
                        <Play className="w-4 h-4 mr-2" />
                        Start Canary
                      </Button>
                    )}
                    {patch.status === 'canary_in_progress' && (
                      <Button
                        onClick={() => rolloutPatch(patch.id)}
                        disabled={loading}
                        size="sm"
                        className="bg-purple-600 hover:bg-purple-700 text-white"
                        data-testid={`rollout-${patch.id}`}
                      >
                        <ArrowRight className="w-4 h-4 mr-2" />
                        Rollout to All
                      </Button>
                    )}
                    {patch.status === 'rolling_out' && (
                      <Button
                        onClick={() => completePatch(patch.id)}
                        disabled={loading}
                        size="sm"
                        className="bg-emerald-600 hover:bg-emerald-700 text-white"
                        data-testid={`complete-${patch.id}`}
                      >
                        <CheckCircle className="w-4 h-4 mr-2" />
                        Mark Complete
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {/* Patches */}
                  <div>
                    <h4 className="text-sm font-medium text-white mb-2">Patches ({patch.patches.length})</h4>
                    <div className="space-y-2">
                      {patch.patches.map((p, idx) => (
                        <div key={idx} className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg border border-slate-700">
                          <div>
                            <p className="text-sm font-medium text-white">{p.name}</p>
                            <p className="text-xs text-slate-500">KB: {p.id}</p>
                          </div>
                          <Badge className={`${getSeverityColor(p.severity)} text-xs`}>
                            {p.severity}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Canary Assets */}
                  <div>
                    <h4 className="text-sm font-medium text-white mb-2">Canary Assets</h4>
                    <div className="flex flex-wrap gap-2">
                      {patch.canary_assets.map((asset, idx) => (
                        <Badge key={idx} variant="outline" className="bg-cyan-500/10 text-cyan-300 border-cyan-500/30">
                          {asset}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Timeline */}
                  <div className="pt-3 border-t border-slate-700">
                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <Clock className="w-3 h-3" />
                      <span>Created: {new Date(patch.created_at).toLocaleString()}</span>
                      {patch.updated_at !== patch.created_at && (
                        <>
                          <span>•</span>
                          <span>Updated: {new Date(patch.updated_at).toLocaleString()}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

export default PatchManagement;