import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { TrendingDown, Clock, CheckCircle, Shield } from 'lucide-react';

const KPIDashboard = ({ kpis, companyId, onRefresh }) => {
  if (!kpis) {
    return null;
  }

  const kpiCards = [
    {
      title: 'Noise Reduction',
      value: `${kpis.noise_reduction_pct}%`,
      subtitle: `${kpis.total_alerts} alerts → ${kpis.total_incidents} incidents`,
      icon: TrendingDown,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/30'
    },
    {
      title: 'Self-Healed',
      value: `${kpis.self_healed_pct}%`,
      subtitle: `${kpis.self_healed_count} auto-resolved`,
      icon: CheckCircle,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10',
      borderColor: 'border-cyan-500/30'
    },
    {
      title: 'MTTR',
      value: `${Math.round(kpis.mttr_minutes)}m`,
      subtitle: 'Mean time to resolve',
      icon: Clock,
      color: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/30'
    },
    {
      title: 'Patch Compliance',
      value: `${kpis.patch_compliance_pct}%`,
      subtitle: 'Systems up to date',
      icon: Shield,
      color: 'text-purple-400',
      bgColor: 'bg-purple-500/10',
      borderColor: 'border-purple-500/30'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4" data-testid="kpi-dashboard">
      {kpiCards.map((kpi, index) => {
        const Icon = kpi.icon;
        return (
          <Card 
            key={index} 
            className={`bg-slate-900/50 border-slate-800 hover:border-slate-700 transition-colors`}
            data-testid={`kpi-card-${kpi.title.toLowerCase().replace(/\s+/g, '-')}`}
          >
            <CardContent className="p-6">
              <div className="flex items-start justify-between mb-4">
                <div className={`w-12 h-12 rounded-xl ${kpi.bgColor} flex items-center justify-center border ${kpi.borderColor}`}>
                  <Icon className={`w-6 h-6 ${kpi.color}`} />
                </div>
              </div>
              <div>
                <p className="text-sm text-slate-400 mb-1">{kpi.title}</p>
                <p className="text-3xl font-bold text-white mb-1" data-testid={`kpi-value-${kpi.title.toLowerCase().replace(/\s+/g, '-')}`}>{kpi.value}</p>
                <p className="text-xs text-slate-500">{kpi.subtitle}</p>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
};

export default KPIDashboard;