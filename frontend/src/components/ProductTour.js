import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { 
  X, ArrowRight, ArrowLeft, Check, 
  BarChart3, Building2, Users, AlertCircle, 
  FileText, Play, TrendingUp, Zap 
} from 'lucide-react';

/**
 * Interactive Product Tour - First-Login Experience
 * Shows users how Alert Whisperer works like a real MSP system
 */
const ProductTour = ({ onComplete }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [isVisible, setIsVisible] = useState(true);

  const tourSteps = [
    {
      id: 0,
      title: '👋 Welcome to Alert Whisperer!',
      description: 'Your complete MSP automation platform. Let me show you how it works in 60 seconds.',
      icon: Zap,
      color: 'cyan',
      position: 'center',
      highlight: null
    },
    {
      id: 1,
      title: '📊 Real-Time Dashboard',
      description: 'Monitor all alerts and incidents across all your client companies in real-time. AI-powered correlation reduces noise by 70%+',
      icon: BarChart3,
      color: 'blue',
      position: 'top-left',
      highlight: '#realtime-dashboard'
    },
    {
      id: 2,
      title: '🏢 Add Client Companies',
      description: 'Onboard new clients with our guided wizard. Install SSM agent → Test connectivity → Create company. Only verified companies are added!',
      icon: Building2,
      color: 'green',
      position: 'top-center',
      highlight: '#companies-tab'
    },
    {
      id: 3,
      title: '👥 Assign Technicians',
      description: 'Create technicians and assign them to companies. Auto-assignment routes incidents based on skills, workload, and priority.',
      icon: Users,
      color: 'purple',
      position: 'top-right',
      highlight: '#technicians-button'
    },
    {
      id: 4,
      title: '🔔 Alert Reception & Correlation',
      description: 'Alerts come in via webhooks → AI correlates similar alerts → Creates incidents → Auto-assigns to best technician.',
      icon: AlertCircle,
      color: 'orange',
      position: 'center-left',
      highlight: '#alerts-section'
    },
    {
      id: 5,
      title: '🚀 Execute Runbooks Remotely',
      description: 'Pre-built runbooks for common issues (disk cleanup, restart services, etc). Execute remotely via AWS SSM - no SSH needed!',
      icon: Play,
      color: 'red',
      position: 'center-right',
      highlight: '#runbooks-section'
    },
    {
      id: 6,
      title: '📈 Track Resolution & KPIs',
      description: 'Monitor MTTR, noise reduction, self-healing rate. Prove ROI with real metrics. Export reports for clients.',
      icon: TrendingUp,
      color: 'teal',
      position: 'bottom',
      highlight: '#kpi-dashboard'
    },
    {
      id: 7,
      title: '✅ You\'re All Set!',
      description: 'That\'s how Alert Whisperer automates your MSP workflow. Start by adding your first client company!',
      icon: Check,
      color: 'green',
      position: 'center',
      highlight: null,
      cta: 'Get Started'
    }
  ];

  const currentTourStep = tourSteps[currentStep];

  const handleNext = () => {
    if (currentStep < tourSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      handleComplete();
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleComplete = () => {
    setIsVisible(false);
    localStorage.setItem('alertWhisperer_tourCompleted', 'true');
    if (onComplete) onComplete();
  };

  const handleSkip = () => {
    handleComplete();
  };

  if (!isVisible) return null;

  const getPositionStyles = () => {
    switch (currentTourStep.position) {
      case 'center':
        return 'fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2';
      case 'top-left':
        return 'fixed top-20 left-8';
      case 'top-center':
        return 'fixed top-20 left-1/2 transform -translate-x-1/2';
      case 'top-right':
        return 'fixed top-20 right-8';
      case 'center-left':
        return 'fixed top-1/2 left-8 transform -translate-y-1/2';
      case 'center-right':
        return 'fixed top-1/2 right-8 transform -translate-y-1/2';
      case 'bottom':
        return 'fixed bottom-8 left-1/2 transform -translate-x-1/2';
      default:
        return 'fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2';
    }
  };

  const Icon = currentTourStep.icon;

  return (
    <>
      {/* Overlay */}
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[9998]" />

      {/* Spotlight effect (optional - highlights the target element) */}
      {currentTourStep.highlight && (
        <div 
          className="fixed inset-0 pointer-events-none z-[9999]"
          style={{
            boxShadow: `0 0 0 9999px rgba(0, 0, 0, 0.6)`
          }}
        />
      )}

      {/* Tour Card */}
      <Card className={`${getPositionStyles()} w-96 bg-slate-800 border-${currentTourStep.color}-500 shadow-2xl z-[10000]`}>
        <CardContent className="p-6">
          {/* Close Button */}
          <button
            onClick={handleSkip}
            className="absolute top-3 right-3 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>

          {/* Step Counter */}
          <div className="flex items-center gap-2 mb-4">
            <div className={`w-10 h-10 rounded-full bg-${currentTourStep.color}-500/20 flex items-center justify-center`}>
              <Icon className={`w-5 h-5 text-${currentTourStep.color}-400`} />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-1">
                {tourSteps.map((_, index) => (
                  <div
                    key={index}
                    className={`h-1 flex-1 rounded-full transition-all ${
                      index === currentStep
                        ? `bg-${currentTourStep.color}-500`
                        : index < currentStep
                        ? `bg-${currentTourStep.color}-600`
                        : 'bg-slate-700'
                    }`}
                  />
                ))}
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Step {currentStep + 1} of {tourSteps.length}
              </p>
            </div>
          </div>

          {/* Content */}
          <div className="mb-6">
            <h3 className="text-xl font-bold text-white mb-2">
              {currentTourStep.title}
            </h3>
            <p className="text-slate-300 text-sm leading-relaxed">
              {currentTourStep.description}
            </p>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-between gap-3">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleSkip}
              className="text-slate-400 hover:text-white"
            >
              Skip Tour
            </Button>

            <div className="flex items-center gap-2">
              {currentStep > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handlePrevious}
                  className="border-slate-600"
                >
                  <ArrowLeft className="w-4 h-4 mr-1" />
                  Back
                </Button>
              )}
              
              <Button
                size="sm"
                onClick={handleNext}
                className={`bg-${currentTourStep.color}-600 hover:bg-${currentTourStep.color}-700`}
              >
                {currentStep === tourSteps.length - 1 ? (
                  <>
                    {currentTourStep.cta || 'Get Started'}
                    <Check className="w-4 h-4 ml-1" />
                  </>
                ) : (
                  <>
                    Next
                    <ArrowRight className="w-4 h-4 ml-1" />
                  </>
                )}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </>
  );
};

/**
 * Hook to check if user should see the tour
 */
export const useShouldShowTour = () => {
  const [shouldShow, setShouldShow] = useState(false);

  useEffect(() => {
    const tourCompleted = localStorage.getItem('alertWhisperer_tourCompleted');
    if (!tourCompleted) {
      // Show tour after a short delay on first load
      setTimeout(() => setShouldShow(true), 1000);
    }
  }, []);

  return shouldShow;
};

export default ProductTour;
