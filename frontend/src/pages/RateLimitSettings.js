import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, AlertTriangle, Activity, Zap } from 'lucide-react';
import { toast } from 'sonner';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';

const RateLimitSettings = ({ companyId, companyName }) => {
  const [rateLimitConfig, setRateLimitConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [formData, setFormData] = useState({
    requests_per_minute: 60,
    burst_size: 100,
    enabled: true
  });

  useEffect(() => {
    if (companyId) {
      loadRateLimitConfig();
    }
  }, [companyId]);

  const loadRateLimitConfig = async () => {
    try {
      const response = await api.get(`/companies/${companyId}/rate-limit`);
      setRateLimitConfig(response.data);
      setFormData({
        requests_per_minute: response.data.requests_per_minute,
        burst_size: response.data.burst_size,
        enabled: response.data.enabled
      });
    } catch (error) {
      console.error('Failed to load rate limit config:', error);
      toast.error('Failed to load rate limit configuration');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      await api.put(
        `/companies/${companyId}/rate-limit?requests_per_minute=${formData.requests_per_minute}&burst_size=${formData.burst_size}&enabled=${formData.enabled}`
      );
      await loadRateLimitConfig();
      setEditing(false);
      toast.success('Rate limit configuration updated');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update rate limit configuration');
    }
  };

  if (loading) {
    return <div className="text-white text-center py-8">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Rate Limiting & Backpressure
          </CardTitle>
          <CardDescription className="text-slate-300">
            Control webhook request rates to protect against bursts and prevent service overload
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Status Card */}
          <div className={`p-4 rounded-lg border ${rateLimitConfig?.enabled ? 'bg-green-500/10 border-green-500/30' : 'bg-orange-500/10 border-orange-500/30'}`}>
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-white font-semibold flex items-center gap-2">
                  {rateLimitConfig?.enabled ? (
                    <Shield className="w-5 h-5 text-green-400" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-orange-400" />
                  )}
                  Rate Limiting Status
                </h3>
                <p className="text-sm text-slate-300 mt-1">
                  {rateLimitConfig?.enabled ? 'Active - Requests are monitored and limited' : 'Disabled - No rate limiting applied'}
                </p>
              </div>
            </div>
          </div>

          {/* Configuration */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-white font-semibold">Configuration</h3>
              {!editing ? (
                <Button
                  onClick={() => setEditing(true)}
                  variant="outline"
                  className="bg-cyan-500/10 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20"
                >
                  Edit Settings
                </Button>
              ) : (
                <div className="flex gap-2">
                  <Button
                    onClick={() => {
                      setEditing(false);
                      setFormData({
                        requests_per_minute: rateLimitConfig.requests_per_minute,
                        burst_size: rateLimitConfig.burst_size,
                        enabled: rateLimitConfig.enabled
                      });
                    }}
                    variant="outline"
                    className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
                  >
                    Cancel
                  </Button>
                  <Button
                    onClick={handleSave}
                    className="bg-green-500/20 border-green-500/30 text-green-400 hover:bg-green-500/30"
                  >
                    Save Changes
                  </Button>
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label className="text-white">Requests Per Minute</Label>
                <Input
                  type="number"
                  min="1"
                  max="1000"
                  value={formData.requests_per_minute}
                  onChange={(e) => setFormData({ ...formData, requests_per_minute: parseInt(e.target.value) })}
                  disabled={!editing}
                  className="bg-slate-800 border-slate-700 text-white disabled:opacity-60"
                />
                <p className="text-xs text-slate-400">
                  Maximum sustained request rate (1-1000)
                </p>
              </div>

              <div className="space-y-2">
                <Label className="text-white">Burst Size</Label>
                <Input
                  type="number"
                  min="1"
                  max="1000"
                  value={formData.burst_size}
                  onChange={(e) => setFormData({ ...formData, burst_size: parseInt(e.target.value) })}
                  disabled={!editing}
                  className="bg-slate-800 border-slate-700 text-white disabled:opacity-60"
                />
                <p className="text-xs text-slate-400">
                  Temporary spike allowance (must be ≥ requests/min)
                </p>
              </div>
            </div>

            <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
              <div>
                <Label className="text-white">Enable Rate Limiting</Label>
                <p className="text-xs text-slate-400 mt-1">
                  Turn rate limiting on or off
                </p>
              </div>
              <Switch
                checked={formData.enabled}
                onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
                disabled={!editing}
              />
            </div>
          </div>

          {/* Current Status */}
          {rateLimitConfig && (
            <div className="space-y-3">
              <h3 className="text-white font-semibold">Current Usage</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700">
                  <div className="text-2xl font-bold text-cyan-400">
                    {rateLimitConfig.current_count || 0}
                  </div>
                  <div className="text-sm text-slate-400 mt-1">Requests in window</div>
                </div>
                <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700">
                  <div className="text-2xl font-bold text-green-400">
                    {rateLimitConfig.requests_per_minute - (rateLimitConfig.current_count || 0)}
                  </div>
                  <div className="text-sm text-slate-400 mt-1">Remaining capacity</div>
                </div>
                <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700">
                  <div className="text-2xl font-bold text-blue-400">
                    {Math.round(((rateLimitConfig.current_count || 0) / rateLimitConfig.requests_per_minute) * 100)}%
                  </div>
                  <div className="text-sm text-slate-400 mt-1">Utilization</div>
                </div>
              </div>
            </div>
          )}

          {/* Information */}
          <div className="space-y-3">
            <h3 className="text-white font-semibold flex items-center gap-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              How It Works
            </h3>
            <div className="space-y-2 text-sm text-slate-300">
              <div className="flex items-start gap-3 p-3 bg-slate-800/30 rounded-lg">
                <div className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-cyan-400 text-xs font-bold">1</span>
                </div>
                <div>
                  <p className="font-medium text-white">Rate Enforcement</p>
                  <p className="text-slate-400 text-xs mt-1">
                    Limits sustained request rate to prevent system overload
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 bg-slate-800/30 rounded-lg">
                <div className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-cyan-400 text-xs font-bold">2</span>
                </div>
                <div>
                  <p className="font-medium text-white">Burst Handling</p>
                  <p className="text-slate-400 text-xs mt-1">
                    Allows temporary spikes above the rate limit for alert storms
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 bg-slate-800/30 rounded-lg">
                <div className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-cyan-400 text-xs font-bold">3</span>
                </div>
                <div>
                  <p className="font-medium text-white">429 Response</p>
                  <p className="text-slate-400 text-xs mt-1">
                    Returns HTTP 429 when limits exceeded with retry information
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Best Practices */}
          <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
            <h3 className="text-white font-semibold mb-2">Best Practices</h3>
            <ul className="space-y-1 text-sm text-slate-300">
              <li>• Set burst_size 1.5-2x higher than requests_per_minute for alert storms</li>
              <li>• Monitor utilization regularly to adjust limits</li>
              <li>• Keep enabled for production environments</li>
              <li>• Alert on 429 responses to detect integration issues</li>
              <li>• Implement exponential backoff in webhook senders</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default RateLimitSettings;
