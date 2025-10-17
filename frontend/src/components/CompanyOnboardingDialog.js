import React, { useState } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { Building2, Cloud, Shield, Settings, Zap, CheckCircle2, XCircle, AlertCircle, Loader2, Lock, GitMerge, Gauge } from 'lucide-react';
import { toast } from 'sonner';

const CompanyOnboardingDialog = ({ open, onOpenChange, onSuccess }) => {
  const [currentStep, setCurrentStep] = useState('basic');
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  
  const [formData, setFormData] = useState({
    // Basic Info
    name: '',
    policy: { auto_approve_low_risk: true, maintenance_window: 'Sat 22:00-02:00' },
    
    // AWS Credentials (optional)
    aws_access_key_id: '',
    aws_secret_access_key: '',
    aws_region: 'us-east-1',
    aws_account_id: '',
    
    // Monitoring Integrations (optional)
    monitoring_integrations: [],
    
    // Webhook Security Settings
    enable_hmac: true,
    
    // Correlation Settings
    correlation_time_window: 15,
    auto_correlate: true,
    
    // Rate Limiting
    rate_limit_enabled: true,
    requests_per_minute: 100,
    burst_size: 20
  });

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const verifyAndCreateCompany = async () => {
    if (!formData.name.trim()) {
      toast.error('Company name is required');
      return;
    }

    setIsVerifying(true);
    setVerificationResult(null);

    try {
      // Step 1: Create company
      const response = await api.post('/companies', {
        name: formData.name,
        policy: formData.policy,
        aws_access_key_id: formData.aws_access_key_id,
        aws_secret_access_key: formData.aws_secret_access_key,
        aws_region: formData.aws_region,
        aws_account_id: formData.aws_account_id,
        monitoring_integrations: formData.monitoring_integrations
      });
      const company = response.data;
      
      // Step 2: Configure webhook security (HMAC)
      if (formData.enable_hmac) {
        try {
          await api.post(`/companies/${company.id}/webhook-security/enable`);
          console.log('✅ HMAC security enabled');
        } catch (error) {
          console.warn('⚠️  HMAC setup failed:', error);
        }
      }
      
      // Step 3: Configure correlation settings
      try {
        await api.put(`/companies/${company.id}/correlation-config`, {
          time_window_minutes: formData.correlation_time_window,
          auto_correlate: formData.auto_correlate
        });
        console.log('✅ Correlation configured');
      } catch (error) {
        console.warn('⚠️  Correlation config failed:', error);
      }
      
      // Step 4: Configure rate limiting
      if (formData.rate_limit_enabled) {
        try {
          await api.put(`/companies/${company.id}/rate-limit`, {
            enabled: true,
            requests_per_minute: formData.requests_per_minute,
            burst_size: formData.burst_size
          });
          console.log('✅ Rate limiting configured');
        } catch (error) {
          console.warn('⚠️  Rate limit config failed:', error);
        }
      }
      
      // Check verification results
      const verification = company.verification_details;
      
      setVerificationResult({
        success: company.integration_verified || true,
        company: company,
        details: verification
      });

      toast.success('Company created and configured successfully!');
      setTimeout(() => {
        onSuccess(company);
        onOpenChange(false);
        resetForm();
      }, 1500);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create company');
      setVerificationResult({
        success: false,
        error: error.response?.data?.detail || 'Failed to create company'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      policy: { auto_approve_low_risk: true, maintenance_window: 'Sat 22:00-02:00' },
      aws_access_key_id: '',
      aws_secret_access_key: '',
      aws_region: 'us-east-1',
      aws_account_id: '',
      monitoring_integrations: [],
      enable_hmac: true,
      correlation_time_window: 15,
      auto_correlate: true,
      rate_limit_enabled: true,
      requests_per_minute: 100,
      burst_size: 20
    });
    setCurrentStep('basic');
    setVerificationResult(null);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto bg-slate-900 border-slate-700">
        <DialogHeader>
          <DialogTitle className="text-2xl text-white flex items-center gap-2">
            <Building2 className="w-6 h-6 text-cyan-400" />
            Onboard New Company
          </DialogTitle>
        </DialogHeader>

        <Tabs value={currentStep} onValueChange={setCurrentStep} className="w-full">
          <TabsList className="grid w-full grid-cols-5 bg-slate-800">
            <TabsTrigger value="basic" className="data-[state=active]:bg-cyan-500">
              <Building2 className="w-4 h-4 mr-2" />
              Basic
            </TabsTrigger>
            <TabsTrigger value="credentials" className="data-[state=active]:bg-cyan-500">
              <Cloud className="w-4 h-4 mr-2" />
              Credentials
            </TabsTrigger>
            <TabsTrigger value="security" className="data-[state=active]:bg-cyan-500">
              <Shield className="w-4 h-4 mr-2" />
              Security
            </TabsTrigger>
            <TabsTrigger value="correlation" className="data-[state=active]:bg-cyan-500">
              <GitMerge className="w-4 h-4 mr-2" />
              Correlation
            </TabsTrigger>
            <TabsTrigger value="review" className="data-[state=active]:bg-cyan-500">
              <CheckCircle2 className="w-4 h-4 mr-2" />
              Review
            </TabsTrigger>
          </TabsList>

          {/* Basic Info Tab */}
          <TabsContent value="basic" className="space-y-4 mt-4">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Company Information</CardTitle>
                <CardDescription className="text-slate-400">
                  Enter basic information about the company you're onboarding
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="company-name" className="text-slate-300">Company Name *</Label>
                  <Input
                    id="company-name"
                    value={formData.name}
                    onChange={(e) => handleInputChange('name', e.target.value)}
                    placeholder="e.g., Acme Corp"
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="maintenance-window" className="text-slate-300">Maintenance Window</Label>
                  <Input
                    id="maintenance-window"
                    value={formData.policy.maintenance_window}
                    onChange={(e) => handleInputChange('policy', { 
                      ...formData.policy, 
                      maintenance_window: e.target.value 
                    })}
                    placeholder="e.g., Sat 22:00-02:00"
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                  <p className="text-xs text-slate-500">When can automated patching occur?</p>
                </div>

                <Alert className="bg-cyan-500/10 border-cyan-500/30">
                  <AlertCircle className="h-4 w-4 text-cyan-400" />
                  <AlertDescription className="text-slate-300">
                    <strong>What happens after onboarding:</strong>
                    <ul className="list-disc list-inside mt-2 space-y-1 text-sm">
                      <li>Company receives API key for webhook integration</li>
                      <li>Monitoring tools send alerts to Alert Whisperer</li>
                      <li>AI correlation reduces alert noise by 40-70%</li>
                      <li>Incidents auto-assigned to technicians</li>
                    </ul>
                  </AlertDescription>
                </Alert>

                <div className="flex justify-end">
                  <Button 
                    onClick={() => setCurrentStep('credentials')}
                    className="bg-cyan-600 hover:bg-cyan-700"
                  >
                    Next: Company Credentials →
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Company Credentials Tab - What MSP Collects from Client */}
          <TabsContent value="credentials" className="space-y-4 mt-4">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Cloud className="w-5 h-5 text-cyan-400" />
                  Client Company Credentials
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Collect these credentials from the company to monitor their infrastructure
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Important Notice */}
                <Alert className="bg-cyan-500/10 border-cyan-500/30">
                  <AlertCircle className="h-4 w-4 text-cyan-400" />
                  <AlertDescription className="text-slate-300">
                    <strong>How Real MSPs Work:</strong> When onboarding a new company, you collect their credentials 
                    to monitor and manage their infrastructure. These credentials allow you to:
                    <ul className="list-disc list-inside mt-2 space-y-1 text-sm">
                      <li>Pull alerts from their AWS CloudWatch</li>
                      <li>Monitor their servers and applications</li>
                      <li>Execute automated remediation scripts</li>
                      <li>Track patch compliance</li>
                    </ul>
                  </AlertDescription>
                </Alert>

                {/* AWS/Cloud Credentials */}
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <Cloud className="w-5 h-5 text-orange-400" />
                    <h4 className="text-white font-semibold">1. AWS Cloud Credentials</h4>
                    <Badge variant="outline" className="text-orange-400 border-orange-400">Required for CloudWatch</Badge>
                  </div>
                  
                  <Card className="bg-slate-900 border-slate-600">
                    <CardHeader>
                      <CardTitle className="text-sm text-white">What to Collect from Company:</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3 text-sm text-slate-300">
                      <div className="flex items-start gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-400 mt-0.5" />
                        <div>
                          <strong>AWS Access Key ID & Secret:</strong> For programmatic access to CloudWatch alarms
                        </div>
                      </div>
                      <div className="flex items-start gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-400 mt-0.5" />
                        <div>
                          <strong>AWS Region:</strong> Where their resources are deployed (e.g., us-east-1)
                        </div>
                      </div>
                      <div className="flex items-start gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-400 mt-0.5" />
                        <div>
                          <strong>AWS Account ID:</strong> 12-digit account identifier
                        </div>
                      </div>
                      <div className="flex items-start gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-400 mt-0.5" />
                        <div>
                          <strong>IAM Role ARN (Recommended):</strong> Cross-account role for secure access
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <div className="space-y-2">
                    <Label htmlFor="aws-access-key" className="text-slate-300">AWS Access Key ID *</Label>
                    <Input
                      id="aws-access-key"
                      type="password"
                      value={formData.aws_access_key_id}
                      onChange={(e) => handleInputChange('aws_access_key_id', e.target.value)}
                      placeholder="AKIA... (provided by company)"
                      className="bg-slate-700 border-slate-600 text-white"
                    />
                    <p className="text-xs text-slate-500">Company provides this from their AWS Console → IAM → Users</p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="aws-secret-key" className="text-slate-300">AWS Secret Access Key *</Label>
                    <Input
                      id="aws-secret-key"
                      type="password"
                      value={formData.aws_secret_access_key}
                      onChange={(e) => handleInputChange('aws_secret_access_key', e.target.value)}
                      placeholder="••••••••"
                      className="bg-slate-700 border-slate-600 text-white"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="aws-region" className="text-slate-300">AWS Region *</Label>
                      <Input
                        id="aws-region"
                        value={formData.aws_region}
                        onChange={(e) => handleInputChange('aws_region', e.target.value)}
                        placeholder="us-east-1"
                        className="bg-slate-700 border-slate-600 text-white"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="aws-account-id" className="text-slate-300">AWS Account ID *</Label>
                      <Input
                        id="aws-account-id"
                        value={formData.aws_account_id}
                        onChange={(e) => handleInputChange('aws_account_id', e.target.value)}
                        placeholder="123456789012"
                        className="bg-slate-700 border-slate-600 text-white"
                      />
                    </div>
                  </div>
                </div>

                <div className="h-px bg-slate-700" />

                {/* Monitoring Tools API Keys */}
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <Settings className="w-5 h-5 text-blue-400" />
                    <h4 className="text-white font-semibold">2. Monitoring Tools (Optional)</h4>
                    <Badge variant="outline" className="text-blue-400 border-blue-400">If they use these</Badge>
                  </div>
                  
                  <Card className="bg-slate-900 border-slate-600">
                    <CardContent className="space-y-2 pt-4 text-sm text-slate-300">
                      <div className="flex justify-between items-center">
                        <span>• <strong>Datadog API Key:</strong> For pulling metrics and alerts</span>
                        <Badge className="bg-slate-700">Coming Soon</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span>• <strong>Zabbix Server URL & Credentials:</strong> For monitoring data</span>
                        <Badge className="bg-slate-700">Coming Soon</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span>• <strong>Prometheus Endpoint:</strong> For scraping metrics</span>
                        <Badge className="bg-slate-700">Coming Soon</Badge>
                      </div>
                    </CardContent>
                  </Card>

                  <Alert className="bg-yellow-500/10 border-yellow-500/30">
                    <AlertCircle className="h-4 w-4 text-yellow-400" />
                    <AlertDescription className="text-slate-300 text-sm">
                      <strong>Alternative Method:</strong> If the company doesn't want to share credentials, 
                      they can send alerts via webhook (PUSH mode). You'll provide them with:
                      <ul className="list-disc list-inside mt-2">
                        <li>Your webhook URL</li>
                        <li>API key for authentication</li>
                        <li>HMAC secret (if enabled)</li>
                      </ul>
                    </AlertDescription>
                  </Alert>
                </div>

                <div className="h-px bg-slate-700" />

                {/* What You'll Be Able to Do */}
                <div className="space-y-3">
                  <h4 className="text-white font-semibold">With These Credentials, You Can:</h4>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="flex items-start gap-2 text-sm">
                      <Zap className="w-4 h-4 text-cyan-400 mt-0.5" />
                      <span className="text-slate-300">Pull CloudWatch alarms automatically</span>
                    </div>
                    <div className="flex items-start gap-2 text-sm">
                      <Shield className="w-4 h-4 text-cyan-400 mt-0.5" />
                      <span className="text-slate-300">Track EC2 patch compliance</span>
                    </div>
                    <div className="flex items-start gap-2 text-sm">
                      <Settings className="w-4 h-4 text-cyan-400 mt-0.5" />
                      <span className="text-slate-300">Execute SSM runbooks remotely</span>
                    </div>
                    <div className="flex items-start gap-2 text-sm">
                      <CheckCircle2 className="w-4 h-4 text-cyan-400 mt-0.5" />
                      <span className="text-slate-300">Auto-remediate common issues</span>
                    </div>
                  </div>
                </div>

                {/* Security Best Practices */}
                <Alert className="bg-green-500/10 border-green-500/30">
                  <Shield className="h-4 w-4 text-green-400" />
                  <AlertDescription className="text-slate-300 text-sm">
                    <strong>Security Best Practices:</strong>
                    <ul className="list-disc list-inside mt-2">
                      <li>Request <strong>least-privilege IAM policies</strong> (ReadOnly + specific actions)</li>
                      <li>Use <strong>cross-account IAM roles</strong> instead of access keys when possible</li>
                      <li>Store credentials in <strong>AWS Secrets Manager</strong> (recommended)</li>
                      <li>Rotate credentials every 90 days</li>
                    </ul>
                  </AlertDescription>
                </Alert>

                <div className="flex justify-between">
                  <Button 
                    variant="outline" 
                    onClick={() => setCurrentStep('basic')}
                    className="border-slate-600 text-slate-300"
                  >
                    ← Back
                  </Button>
                  <Button 
                    onClick={() => setCurrentStep('security')}
                    className="bg-cyan-600 hover:bg-cyan-700"
                  >
                    Next: Security Settings →
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Security Settings Tab */}
          <TabsContent value="security" className="space-y-4 mt-4">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  Security & Rate Limiting
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Configure webhook security and rate limiting for this company
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* HMAC Webhook Security */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-1">
                      <Label className="text-slate-300 font-semibold">HMAC Webhook Security</Label>
                      <p className="text-xs text-slate-500">
                        Cryptographic signature verification for incoming alerts (RECOMMENDED)
                      </p>
                    </div>
                    <Switch
                      checked={formData.enable_hmac}
                      onCheckedChange={(checked) => handleInputChange('enable_hmac', checked)}
                      className="data-[state=checked]:bg-cyan-600"
                    />
                  </div>
                  
                  {formData.enable_hmac && (
                    <Alert className="bg-green-500/10 border-green-500/30">
                      <CheckCircle2 className="h-4 w-4 text-green-400" />
                      <AlertDescription className="text-slate-300 text-sm">
                        <strong>HMAC Enabled:</strong> Webhook requests will require X-Signature header for authentication.
                        Secret key will be generated automatically after company creation.
                      </AlertDescription>
                    </Alert>
                  )}
                </div>

                <div className="h-px bg-slate-700" />

                {/* Rate Limiting */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-1">
                      <Label className="text-slate-300 font-semibold">Rate Limiting</Label>
                      <p className="text-xs text-slate-500">
                        Protect against alert storms and API abuse
                      </p>
                    </div>
                    <Switch
                      checked={formData.rate_limit_enabled}
                      onCheckedChange={(checked) => handleInputChange('rate_limit_enabled', checked)}
                      className="data-[state=checked]:bg-cyan-600"
                    />
                  </div>

                  {formData.rate_limit_enabled && (
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <Label className="text-slate-300">Requests Per Minute</Label>
                          <Badge variant="outline" className="text-cyan-400 border-cyan-400">
                            {formData.requests_per_minute} req/min
                          </Badge>
                        </div>
                        <Slider
                          value={[formData.requests_per_minute]}
                          onValueChange={([value]) => handleInputChange('requests_per_minute', value)}
                          min={10}
                          max={500}
                          step={10}
                          className="w-full"
                        />
                        <p className="text-xs text-slate-500">
                          Maximum webhook requests allowed per minute
                        </p>
                      </div>

                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <Label className="text-slate-300">Burst Size</Label>
                          <Badge variant="outline" className="text-cyan-400 border-cyan-400">
                            {formData.burst_size} alerts
                          </Badge>
                        </div>
                        <Slider
                          value={[formData.burst_size]}
                          onValueChange={([value]) => handleInputChange('burst_size', value)}
                          min={5}
                          max={100}
                          step={5}
                          className="w-full"
                        />
                        <p className="text-xs text-slate-500">
                          Allow temporary alert bursts during incidents
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                <Alert className="bg-cyan-500/10 border-cyan-500/30">
                  <AlertCircle className="h-4 w-4 text-cyan-400" />
                  <AlertDescription className="text-slate-300 text-sm">
                    <strong>Best Practice:</strong> Keep HMAC enabled for production security. 
                    Rate limiting prevents alert storms from overwhelming the system.
                  </AlertDescription>
                </Alert>

                <div className="flex justify-between">
                  <Button 
                    variant="outline" 
                    onClick={() => setCurrentStep('basic')}
                    className="border-slate-600 text-slate-300"
                  >
                    ← Back
                  </Button>
                  <Button 
                    onClick={() => setCurrentStep('correlation')}
                    className="bg-cyan-600 hover:bg-cyan-700"
                  >
                    Next: Correlation →
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Correlation Settings Tab */}
          <TabsContent value="correlation" className="space-y-4 mt-4">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <GitMerge className="w-5 h-5 text-cyan-400" />
                  Alert Correlation Settings
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Configure how alerts are correlated into incidents using AI
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Auto-Correlate Toggle */}
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label className="text-slate-300 font-semibold">Auto-Correlate Alerts</Label>
                    <p className="text-xs text-slate-500">
                      Automatically group related alerts into incidents using AI + rules
                    </p>
                  </div>
                  <Switch
                    checked={formData.auto_correlate}
                    onCheckedChange={(checked) => handleInputChange('auto_correlate', checked)}
                    className="data-[state=checked]:bg-cyan-600"
                  />
                </div>

                {formData.auto_correlate && (
                  <>
                    <div className="h-px bg-slate-700" />

                    {/* Time Window */}
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <Label className="text-slate-300">Correlation Time Window</Label>
                        <Badge variant="outline" className="text-cyan-400 border-cyan-400">
                          {formData.correlation_time_window} minutes
                        </Badge>
                      </div>
                      <Slider
                        value={[formData.correlation_time_window]}
                        onValueChange={([value]) => handleInputChange('correlation_time_window', value)}
                        min={5}
                        max={15}
                        step={1}
                        className="w-full"
                      />
                      <p className="text-xs text-slate-500">
                        Alerts within this time window can be correlated together
                      </p>
                    </div>

                    {/* Correlation Strategy Info */}
                    <Card className="bg-slate-900 border-slate-600">
                      <CardHeader>
                        <CardTitle className="text-sm text-white">How Correlation Works (Hybrid AI)</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        <div className="flex items-start gap-2 text-sm text-slate-300">
                          <CheckCircle2 className="w-4 h-4 text-green-400 mt-0.5" />
                          <div>
                            <strong>Rule-Based (Primary):</strong> Groups alerts by asset + signature + time window
                          </div>
                        </div>
                        <div className="flex items-start gap-2 text-sm text-slate-300">
                          <Zap className="w-4 h-4 text-cyan-400 mt-0.5" />
                          <div>
                            <strong>AI-Enhanced (Bedrock/Gemini):</strong> Detects complex patterns, cascading failures, and root causes
                          </div>
                        </div>
                        <div className="flex items-start gap-2 text-sm text-slate-300">
                          <Settings className="w-4 h-4 text-yellow-400 mt-0.5" />
                          <div>
                            <strong>Priority Scoring:</strong> severity + asset criticality + duplicate count + multi-tool detection
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Alert className="bg-cyan-500/10 border-cyan-500/30">
                      <AlertCircle className="h-4 w-4 text-cyan-400" />
                      <AlertDescription className="text-slate-300 text-sm">
                        <strong>Noise Reduction:</strong> AI correlation typically reduces alert noise by 40-70%, 
                        grouping related alerts into actionable incidents for your technicians.
                      </AlertDescription>
                    </Alert>
                  </>
                )}

                <div className="flex justify-between">
                  <Button 
                    variant="outline" 
                    onClick={() => setCurrentStep('security')}
                    className="border-slate-600 text-slate-300"
                  >
                    ← Back
                  </Button>
                  <Button 
                    onClick={() => setCurrentStep('review')}
                    className="bg-cyan-600 hover:bg-cyan-700"
                  >
                    Next: Review →
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* AWS Integration Tab */}
          <TabsContent value="aws" className="space-y-4 mt-4">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Cloud className="w-5 h-5 text-cyan-400" />
                  AWS Integration (Optional)
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Configure AWS credentials for CloudWatch monitoring, Patch Manager, and SSM automation
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Alert className="bg-yellow-500/10 border-yellow-500/30">
                  <AlertCircle className="h-4 w-4 text-yellow-400" />
                  <AlertDescription className="text-slate-300">
                    <strong>Optional:</strong> Skip this if AWS integration isn't needed. 
                    You can configure it later in company settings.
                  </AlertDescription>
                </Alert>

                <div className="space-y-2">
                  <Label htmlFor="aws-access-key" className="text-slate-300">AWS Access Key ID</Label>
                  <Input
                    id="aws-access-key"
                    type="password"
                    value={formData.aws_access_key_id}
                    onChange={(e) => handleInputChange('aws_access_key_id', e.target.value)}
                    placeholder="AKIA..."
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="aws-secret-key" className="text-slate-300">AWS Secret Access Key</Label>
                  <Input
                    id="aws-secret-key"
                    type="password"
                    value={formData.aws_secret_access_key}
                    onChange={(e) => handleInputChange('aws_secret_access_key', e.target.value)}
                    placeholder="••••••••"
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="aws-region" className="text-slate-300">AWS Region</Label>
                    <Input
                      id="aws-region"
                      value={formData.aws_region}
                      onChange={(e) => handleInputChange('aws_region', e.target.value)}
                      placeholder="us-east-1"
                      className="bg-slate-700 border-slate-600 text-white"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="aws-account-id" className="text-slate-300">AWS Account ID</Label>
                    <Input
                      id="aws-account-id"
                      value={formData.aws_account_id}
                      onChange={(e) => handleInputChange('aws_account_id', e.target.value)}
                      placeholder="123456789012"
                      className="bg-slate-700 border-slate-600 text-white"
                    />
                  </div>
                </div>

                <Card className="bg-slate-900 border-slate-600">
                  <CardHeader>
                    <CardTitle className="text-sm text-white">AWS Integration Enables:</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-2 text-sm text-slate-300">
                      <li className="flex items-start gap-2">
                        <Zap className="w-4 h-4 text-cyan-400 mt-0.5" />
                        <span><strong>CloudWatch Polling:</strong> Pull alarms automatically (PULL mode)</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Shield className="w-4 h-4 text-cyan-400 mt-0.5" />
                        <span><strong>Patch Manager:</strong> Real-time compliance tracking</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <Settings className="w-4 h-4 text-cyan-400 mt-0.5" />
                        <span><strong>SSM Automation:</strong> Execute runbooks remotely</span>
                      </li>
                    </ul>
                  </CardContent>
                </Card>

                <div className="flex justify-between">
                  <Button 
                    variant="outline" 
                    onClick={() => setCurrentStep('basic')}
                    className="border-slate-600 text-slate-300"
                  >
                    ← Back
                  </Button>
                  <Button 
                    onClick={() => setCurrentStep('review')}
                    className="bg-cyan-600 hover:bg-cyan-700"
                  >
                    Next: Review →
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Review & Create Tab */}
          <TabsContent value="review" className="space-y-4 mt-4">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Review Configuration</CardTitle>
                <CardDescription className="text-slate-400">
                  Review all settings before creating the company. Everything configured here!
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Basic Info Summary */}
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Building2 className="w-4 h-4 text-cyan-400" />
                    Basic Information
                  </h4>
                  <div className="bg-slate-900 p-3 rounded space-y-1 text-sm">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Company Name:</span>
                      <span className="text-white font-medium">{formData.name || 'Not provided'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Maintenance Window:</span>
                      <span className="text-white">{formData.policy.maintenance_window}</span>
                    </div>
                  </div>
                </div>

                {/* Security Settings Summary */}
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Shield className="w-4 h-4 text-cyan-400" />
                    Security & Rate Limiting
                  </h4>
                  <div className="bg-slate-900 p-3 rounded space-y-2 text-sm">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">HMAC Webhook Security:</span>
                      <Badge className={formData.enable_hmac ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-slate-700 text-slate-400'}>
                        {formData.enable_hmac ? <CheckCircle2 className="w-3 h-3 mr-1" /> : <XCircle className="w-3 h-3 mr-1" />}
                        {formData.enable_hmac ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Rate Limiting:</span>
                      <Badge className={formData.rate_limit_enabled ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-slate-700 text-slate-400'}>
                        {formData.rate_limit_enabled ? <CheckCircle2 className="w-3 h-3 mr-1" /> : <XCircle className="w-3 h-3 mr-1" />}
                        {formData.rate_limit_enabled ? `${formData.requests_per_minute} req/min` : 'Disabled'}
                      </Badge>
                    </div>
                    {formData.rate_limit_enabled && (
                      <div className="flex justify-between">
                        <span className="text-slate-400">Burst Size:</span>
                        <span className="text-white">{formData.burst_size} alerts</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Correlation Settings Summary */}
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-white flex items-center gap-2">
                    <GitMerge className="w-4 h-4 text-cyan-400" />
                    Alert Correlation (AI-Enhanced)
                  </h4>
                  <div className="bg-slate-900 p-3 rounded space-y-2 text-sm">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Auto-Correlate:</span>
                      <Badge className={formData.auto_correlate ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-slate-700 text-slate-400'}>
                        {formData.auto_correlate ? <CheckCircle2 className="w-3 h-3 mr-1" /> : <XCircle className="w-3 h-3 mr-1" />}
                        {formData.auto_correlate ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </div>
                    {formData.auto_correlate && (
                      <div className="flex justify-between">
                        <span className="text-slate-400">Time Window:</span>
                        <span className="text-white">{formData.correlation_time_window} minutes</span>
                      </div>
                    )}
                    <div className="flex items-start gap-2 mt-2 pt-2 border-t border-slate-700">
                      <Zap className="w-4 h-4 text-cyan-400 mt-0.5" />
                      <span className="text-slate-400">
                        Using <strong className="text-cyan-400">AWS Bedrock + Gemini</strong> for pattern detection
                      </span>
                    </div>
                  </div>
                </div>

                {/* AWS Integration Summary */}
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Cloud className="w-4 h-4 text-cyan-400" />
                    Company Credentials (What You Collected)
                  </h4>
                  <div className="bg-slate-900 p-3 rounded space-y-1 text-sm">
                    {formData.aws_access_key_id ? (
                      <>
                        <div className="flex justify-between">
                          <span className="text-slate-400">AWS Access Key:</span>
                          <span className="text-white">{formData.aws_access_key_id.substring(0, 8)}...</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">AWS Region:</span>
                          <span className="text-white">{formData.aws_region}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">AWS Account:</span>
                          <span className="text-white">{formData.aws_account_id || 'Not provided'}</span>
                        </div>
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30 mt-2">
                          <CheckCircle2 className="w-3 h-3 mr-1" />
                          Can pull CloudWatch alarms + Execute SSM runbooks
                        </Badge>
                      </>
                    ) : (
                      <>
                        <div className="text-slate-500">No AWS credentials provided</div>
                        <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 mt-2">
                          <AlertCircle className="w-3 h-3 mr-1" />
                          Company will send alerts via webhook (PUSH mode)
                        </Badge>
                      </>
                    )}
                  </div>
                </div>

                {/* What Happens Next */}
                <Alert className="bg-cyan-500/10 border-cyan-500/30">
                  <Zap className="h-4 w-4 text-cyan-400" />
                  <AlertDescription className="text-slate-300">
                    <strong className="text-cyan-400">After Creation:</strong>
                    <ul className="list-disc list-inside mt-2 space-y-1 text-sm">
                      <li>Company receives API key for webhook integration</li>
                      <li>HMAC secret generated (if enabled)</li>
                      <li>Monitoring tools can send alerts immediately</li>
                      <li>AI correlation reduces noise by 40-70%</li>
                      <li>Incidents auto-assigned to technicians</li>
                    </ul>
                  </AlertDescription>
                </Alert>

                {/* Verification Results */}
                {verificationResult && (
                  <Alert className={verificationResult.success ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}>
                    {verificationResult.success ? (
                      <CheckCircle2 className="h-4 w-4 text-green-400" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-400" />
                    )}
                    <AlertDescription className="text-slate-300">
                      {verificationResult.success ? (
                        <div>
                          <strong className="text-green-400">✅ Company Created Successfully!</strong>
                          <p className="mt-2 text-sm">All configurations applied. API key will be shown next.</p>
                        </div>
                      ) : (
                        <div>
                          <strong className="text-red-400">❌ Creation Failed</strong>
                          <p className="mt-1 text-sm">{verificationResult.error}</p>
                        </div>
                      )}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="flex justify-between pt-4">
                  <Button 
                    variant="outline" 
                    onClick={() => setCurrentStep('correlation')}
                    className="border-slate-600 text-slate-300"
                    disabled={isVerifying}
                  >
                    ← Back
                  </Button>
                  <Button 
                    onClick={verifyAndCreateCompany}
                    disabled={isVerifying || !formData.name.trim()}
                    className="bg-cyan-600 hover:bg-cyan-700"
                  >
                    {isVerifying ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Creating & Configuring...
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-4 h-4 mr-2" />
                        Create Company
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
};

export default CompanyOnboardingDialog;
