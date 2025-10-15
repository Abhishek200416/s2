import React, { useState } from 'react';
import { Play, CheckCircle, XCircle, Clock, Terminal, Zap } from 'lucide-react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { toast } from 'sonner';

const SSMExecutionButton = ({ incident, runbook, onExecutionComplete }) => {
  const [executing, setExecuting] = useState(false);
  const [showDetailsDialog, setShowDetailsDialog] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);

  const executeRunbook = async () => {
    setExecuting(true);
    try {
      const response = await api.post(`/incidents/${incident.id}/execute-runbook-ssm`, {
        runbook_id: runbook.id,
        instance_ids: [] // Will use mock instances
      });
      
      setExecutionResult(response.data);
      toast.success('Runbook executed successfully via AWS SSM');
      setShowDetailsDialog(true);
      
      if (onExecutionComplete) {
        onExecutionComplete(response.data);
      }
    } catch (error) {
      console.error('Failed to execute runbook:', error);
      toast.error('Failed to execute runbook');
    }
    setExecuting(false);
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'Success':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'Failed':
        return <XCircle className="w-4 h-4 text-red-400" />;
      case 'InProgress':
        return <Clock className="w-4 h-4 text-yellow-400 animate-spin" />;
      default:
        return <Terminal className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'Success':
        return 'bg-green-500/10 text-green-400 border-green-500/20';
      case 'Failed':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'InProgress':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      default:
        return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
    }
  };

  // Show execution status if incident has SSM data
  if (incident.ssm_command_id) {
    return (
      <>
        <div className="flex items-center gap-2">
          <Badge className={`flex items-center gap-1 ${getStatusColor(incident.remediation_status)}`}>
            {getStatusIcon(incident.remediation_status)}
            <span>SSM: {incident.remediation_status}</span>
          </Badge>
          {incident.auto_remediated && (
            <Badge className="bg-green-500/10 text-green-400 border-green-500/20 flex items-center gap-1">
              <Zap className="w-3 h-3" />
              Self-Healed
            </Badge>
          )}
          {incident.remediation_duration_seconds && (
            <span className="text-xs text-gray-400">
              in {incident.remediation_duration_seconds}s
            </span>
          )}
        </div>

        <Dialog open={showDetailsDialog} onOpenChange={setShowDetailsDialog}>
          <DialogContent className="bg-slate-900 border-slate-800 text-white">
            <DialogHeader>
              <DialogTitle>SSM Execution Details</DialogTitle>
              <DialogDescription className="text-slate-400">
                AWS Systems Manager Run Command execution
              </DialogDescription>
            </DialogHeader>
            {executionResult && (
              <div className="space-y-4">
                <div>
                  <p className="text-xs text-slate-500 mb-1">Command ID</p>
                  <code className="text-sm text-cyan-400 bg-slate-800 px-2 py-1 rounded">
                    {executionResult.command_id}
                  </code>
                </div>
                <div>
                  <p className="text-xs text-slate-500 mb-1">Status</p>
                  <Badge className={getStatusColor(executionResult.status)}>
                    {executionResult.status}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-slate-500 mb-1">Duration</p>
                  <p className="text-white">{executionResult.duration_seconds} seconds</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 mb-1">Target Instances</p>
                  <div className="space-y-1">
                    {executionResult.instance_ids.map((id) => (
                      <code key={id} className="text-sm text-gray-300 bg-slate-800 px-2 py-1 rounded block">
                        {id}
                      </code>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </>
    );
  }

  // Show execute button if runbook available and not yet executed
  return (
    <Button
      onClick={executeRunbook}
      disabled={executing}
      size="sm"
      className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white"
    >
      {executing ? (
        <>
          <Clock className="w-4 h-4 mr-2 animate-spin" />
          Executing...
        </>
      ) : (
        <>
          <Play className="w-4 h-4 mr-2" />
          Execute via SSM
        </>
      )}
    </Button>
  );
};

export default SSMExecutionButton;
