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
import { Building2, Cloud, Shield, Settings, Zap, CheckCircle2, XCircle, AlertCircle, Loader2 } from 'lucide-react';
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
    monitoring_integrations: []
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
      // Create company with verification
      const response = await api.post('/companies', formData);
      const company = response.data;
      
      // Check verification results
      const verification = company.verification_details;
      
      setVerificationResult({
        success: company.integration_verified,
        company: company,
        details: verification
      });

      if (company.integration_verified) {
        toast.success('Company created and integrations verified!');
        setTimeout(() => {
          onSuccess(company);
          onOpenChange(false);
          resetForm();
        }, 2000);
      } else {
        // Partial success - company created but some integrations failed
        if (verification?.aws && !verification.aws.verified) {
          toast.warning('Company created but AWS integration failed: ' + verification.aws.error);
        } else {
          toast.success('Company created successfully');
          onSuccess(company);
          onOpenChange(false);
          resetForm();
        }
      }
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
      monitoring_integrations: []
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
          <TabsList className="grid w-full grid-cols-3 bg-slate-800">
            <TabsTrigger value="basic" className="data-[state=active]:bg-cyan-500">
              <Building2 className="w-4 h-4 mr-2" />
              Basic Info
            </TabsTrigger>
            <TabsTrigger value="aws" className="data-[state=active]:bg-cyan-500">
              <Cloud className="w-4 h-4 mr-2" />
              AWS Integration
            </TabsTrigger>
            <TabsTrigger value="review" className="data-[state=active]:bg-cyan-500">
              <Settings className="w-4 h-4 mr-2" />
              Review & Create
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
                    onClick={() => setCurrentStep('aws')}
                    className="bg-cyan-600 hover:bg-cyan-700"
                  >
                    Next: AWS Integration →
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
                  Review and confirm the company configuration before creating
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Basic Info Summary */}
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-white">Basic Information</h4>
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

                {/* AWS Integration Summary */}
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-white">AWS Integration</h4>
                  <div className="bg-slate-900 p-3 rounded space-y-1 text-sm">
                    {formData.aws_access_key_id ? (
                      <>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Access Key ID:</span>
                          <span className="text-white">{formData.aws_access_key_id.substring(0, 8)}...</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Region:</span>
                          <span className="text-white">{formData.aws_region}</span>
                        </div>
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                          <CheckCircle2 className="w-3 h-3 mr-1" />
                          Will be verified
                        </Badge>
                      </>
                    ) : (
                      <div className="text-slate-500">Not configured (can be added later)</div>
                    )}
                  </div>
                </div>

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
                          <strong className="text-green-400">✅ Integration Verified!</strong>
                          <ul className="mt-2 space-y-1 text-sm">
                            {verificationResult.details?.webhook?.verified && (
                              <li>✓ Webhook endpoint ready</li>
                            )}
                            {verificationResult.details?.aws?.verified && (
                              <li>✓ AWS credentials verified</li>
                            )}
                          </ul>
                        </div>
                      ) : (
                        <div>
                          <strong className="text-red-400">❌ Verification Failed</strong>
                          <p className="mt-1 text-sm">{verificationResult.error}</p>
                          {verificationResult.details?.aws && !verificationResult.details.aws.verified && (
                            <p className="mt-1 text-sm">AWS Error: {verificationResult.details.aws.error}</p>
                          )}
                        </div>
                      )}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="flex justify-between pt-4">
                  <Button 
                    variant="outline" 
                    onClick={() => setCurrentStep('aws')}
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
                        Verifying & Creating...
                      </>
                    ) : (
                      'Create Company'
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
