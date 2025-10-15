import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Shield, LogOut, AlertTriangle, TrendingDown, Clock, CheckCircle, 
  Play, XCircle, ArrowRight, Activity, Database, Zap, FileText, User, Settings, Bell
} from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import RealTimeDashboard from '../components/RealTimeDashboard';
import AlertCorrelation from '../components/AlertCorrelation';
import IncidentList from '../components/IncidentList';
import DecisionEngine from '../components/DecisionEngine';
import PatchManagement from '../components/PatchManagement';
import KPIDashboard from '../components/KPIDashboard';
import CompanyManagement from '../components/CompanyManagement';
import ActivityFeed from '../components/ActivityFeed';

const Dashboard = ({ user, onLogout }) => {
  const navigate = useNavigate();
  const [companies, setCompanies] = useState([]);
  const [selectedCompany, setSelectedCompany] = useState(null);
  const [kpis, setKpis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [unreadCount, setUnreadCount] = useState(0);

  useEffect(() => {
    loadCompanies();
    loadUnreadCount();
    // Poll for unread notifications every 30 seconds
    const interval = setInterval(loadUnreadCount, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedCompany) {
      loadKPIs();
    }
  }, [selectedCompany]);

  const loadUnreadCount = async () => {
    try {
      const response = await api.get('/notifications/unread-count');
      setUnreadCount(response.data.count);
    } catch (error) {
      console.error('Failed to load unread count:', error);
    }
  };

  const loadCompanies = async () => {
    try {
      const response = await api.get('/companies');
      setCompanies(response.data);
      
      // Auto-select first company the user has access to
      if (response.data.length > 0) {
        const userCompanies = response.data.filter(c => 
          user.company_ids.includes(c.id)
        );
        if (userCompanies.length > 0) {
          setSelectedCompany(userCompanies[0].id);
        }
      }
    } catch (error) {
      console.error('Failed to load companies:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadKPIs = async () => {
    try {
      const response = await api.get(`/kpis/${selectedCompany}`);
      setKpis(response.data);
    } catch (error) {
      console.error('Failed to load KPIs:', error);
    }
  };

  const userCompanies = companies.filter(c => user.company_ids.includes(c.id));
  const currentCompany = companies.find(c => c.id === selectedCompany);

  return (
    <div className="min-h-screen bg-slate-950" data-testid="dashboard">
      {/* Header */}
      <header className="bg-slate-900/50 border-b border-slate-800 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-[1920px] mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-cyan-500/20 rounded-xl flex items-center justify-center border border-cyan-500/30">
                  <Shield className="w-5 h-5 text-cyan-400" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-white">Alert Whisperer</h1>
                  <p className="text-xs text-slate-400">Operations Intelligence</p>
                </div>
              </div>

              {/* Company Selector */}
              <div className="ml-8">
                <Select value={selectedCompany} onValueChange={setSelectedCompany}>
                  <SelectTrigger className="w-[250px] bg-slate-800/50 border-slate-700 text-white" data-testid="company-selector">
                    <SelectValue placeholder="Select company" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-700">
                    {userCompanies.map((company) => (
                      <SelectItem key={company.id} value={company.id} className="text-white hover:bg-slate-700">
                        {company.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <Button
                onClick={() => navigate('/technicians')}
                variant="outline"
                size="sm"
                className="border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white"
              >
                <Settings className="w-4 h-4 mr-2" />
                Technicians
              </Button>
              
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" className="text-white hover:bg-slate-800">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 bg-cyan-500/20 rounded-full flex items-center justify-center border border-cyan-500/30">
                        <User className="w-4 h-4 text-cyan-400" />
                      </div>
                      <div className="text-left">
                        <p className="text-sm font-medium">{user.name}</p>
                        <p className="text-xs text-slate-400">{user.role}</p>
                      </div>
                    </div>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent className="w-48 bg-slate-900 border-slate-800" align="end">
                  <DropdownMenuLabel className="text-slate-300">My Account</DropdownMenuLabel>
                  <DropdownMenuSeparator className="bg-slate-800" />
                  <DropdownMenuItem 
                    onClick={() => navigate('/profile')}
                    className="text-slate-300 focus:bg-slate-800 focus:text-white cursor-pointer"
                  >
                    <User className="w-4 h-4 mr-2" />
                    Profile Settings
                  </DropdownMenuItem>
                  <DropdownMenuSeparator className="bg-slate-800" />
                  <DropdownMenuItem 
                    onClick={onLogout}
                    className="text-red-400 focus:bg-red-500/10 focus:text-red-400 cursor-pointer"
                  >
                    <LogOut className="w-4 h-4 mr-2" />
                    Logout
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1920px] mx-auto px-6 py-6">
        {!selectedCompany ? (
          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="py-12 text-center">
              <AlertTriangle className="w-12 h-12 text-slate-500 mx-auto mb-4" />
              <p className="text-slate-400">Please select a company to view operations</p>
            </CardContent>
          </Card>
        ) : (
          <>
            {/* KPI Overview */}
            <div className="mb-6">
              <KPIDashboard kpis={kpis} companyId={selectedCompany} onRefresh={loadKPIs} />
            </div>

            {/* Tabs */}
            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
              <TabsList className="bg-slate-900/50 border border-slate-800 p-1">
                <TabsTrigger 
                  value="overview" 
                  className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
                  data-testid="tab-overview"
                >
                  <Activity className="w-4 h-4 mr-2" />
                  Overview
                </TabsTrigger>
                <TabsTrigger 
                  value="correlation" 
                  className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
                  data-testid="tab-correlation"
                >
                  <Zap className="w-4 h-4 mr-2" />
                  Alert Correlation
                </TabsTrigger>
                <TabsTrigger 
                  value="incidents" 
                  className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
                  data-testid="tab-incidents"
                >
                  <AlertTriangle className="w-4 h-4 mr-2" />
                  Incidents
                </TabsTrigger>
                <TabsTrigger 
                  value="patches" 
                  className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
                  data-testid="tab-patches"
                >
                  <Database className="w-4 h-4 mr-2" />
                  Patches
                </TabsTrigger>
                {user.role === 'admin' && (
                  <TabsTrigger 
                    value="companies" 
                    className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
                    data-testid="tab-companies"
                  >
                    <Shield className="w-4 h-4 mr-2" />
                    Companies
                  </TabsTrigger>
                )}
              </TabsList>

              <TabsContent value="overview" className="space-y-6">
                <RealTimeDashboard 
                  companyId={selectedCompany} 
                  companyName={currentCompany?.name} 
                />
              </TabsContent>

              <TabsContent value="correlation">
                <AlertCorrelation companyId={selectedCompany} companyName={currentCompany?.name} />
              </TabsContent>

              <TabsContent value="incidents">
                <IncidentList companyId={selectedCompany} />
              </TabsContent>

              <TabsContent value="patches">
                <PatchManagement companyId={selectedCompany} />
              </TabsContent>

              {user.role === 'admin' && (
                <TabsContent value="companies">
                  <CompanyManagement onCompanyChange={loadCompanies} />
                </TabsContent>
              )}
            </Tabs>
          </>
        )}
      </main>
    </div>
  );
};

export default Dashboard;