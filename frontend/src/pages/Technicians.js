import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Users, Plus, Trash2, Mail, Shield, UserCircle, Edit } from 'lucide-react';
import { toast } from 'sonner';

const Technicians = () => {
  const [technicians, setTechnicians] = useState([]);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [selectedTechnician, setSelectedTechnician] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    role: 'technician'
  });

  useEffect(() => {
    loadTechnicians();
  }, []);

  const loadTechnicians = async () => {
    try {
      const response = await api.get('/users');
      // Filter to show only technicians
      const techUsers = response.data.filter(user => user.role === 'technician');
      setTechnicians(techUsers);
    } catch (error) {
      console.error('Failed to load technicians:', error);
      toast.error('Failed to load technicians');
    }
  };

  const createTechnician = async () => {
    if (!formData.name || !formData.email || !formData.password) {
      toast.error('Please fill all required fields');
      return;
    }

    try {
      await api.post('/users', formData);
      toast.success('Technician created successfully');
      setShowCreateDialog(false);
      resetForm();
      await loadTechnicians();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create technician');
    }
  };

  const updateTechnician = async () => {
    if (!formData.name || !formData.email) {
      toast.error('Please fill all required fields');
      return;
    }

    try {
      const updateData = { name: formData.name, email: formData.email };
      if (formData.password) {
        updateData.password = formData.password;
      }
      await api.put(`/users/${selectedTechnician.id}`, updateData);
      toast.success('Technician updated successfully');
      setShowEditDialog(false);
      resetForm();
      await loadTechnicians();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update technician');
    }
  };

  const deleteTechnician = async (techId, techName) => {
    if (!window.confirm(`Are you sure you want to delete ${techName}? This action cannot be undone.`)) {
      return;
    }

    try {
      await api.delete(`/users/${techId}`);
      toast.success('Technician deleted successfully');
      await loadTechnicians();
    } catch (error) {
      toast.error('Failed to delete technician');
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      email: '',
      password: '',
      role: 'technician'
    });
    setSelectedTechnician(null);
  };

  const openEditDialog = (technician) => {
    setSelectedTechnician(technician);
    setFormData({
      name: technician.name,
      email: technician.email,
      password: '',
      role: 'technician'
    });
    setShowEditDialog(true);
  };

  return (
    <div className="min-h-screen bg-slate-950 py-8">
      <div className="max-w-7xl mx-auto px-6">
        <Card className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-purple-500/30 mb-6">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-white text-3xl flex items-center gap-3">
                  <Users className="w-8 h-8 text-purple-400" />
                  Technician Management
                </CardTitle>
                <CardDescription className="text-slate-300 mt-2 text-base">
                  Manage technicians who handle alerts and incidents
                </CardDescription>
              </div>
              <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
                <DialogTrigger asChild>
                  <Button className="bg-purple-600 hover:bg-purple-700 text-white">
                    <Plus className="w-4 h-4 mr-2" />
                    Add Technician
                  </Button>
                </DialogTrigger>
                <DialogContent className="bg-slate-900 border-slate-800 text-white max-w-md">
                  <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                      <UserCircle className="w-5 h-5 text-purple-400" />
                      Create New Technician
                    </DialogTitle>
                    <DialogDescription className="text-slate-400">
                      Add a new technician to handle alerts and incidents
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 mt-4">
                    <div>
                      <Label className="text-white">Full Name *</Label>
                      <Input
                        value={formData.name}
                        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                        placeholder="e.g., John Smith"
                        className="bg-slate-800 border-slate-700 text-white mt-1"
                      />
                    </div>

                    <div>
                      <Label className="text-white">Email Address *</Label>
                      <Input
                        type="email"
                        value={formData.email}
                        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                        placeholder="john.smith@company.com"
                        className="bg-slate-800 border-slate-700 text-white mt-1"
                      />
                    </div>

                    <div>
                      <Label className="text-white">Password *</Label>
                      <Input
                        type="password"
                        value={formData.password}
                        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                        placeholder="Create a strong password"
                        className="bg-slate-800 border-slate-700 text-white mt-1"
                      />
                      <p className="text-xs text-slate-500 mt-1">Minimum 6 characters</p>
                    </div>

                    <Button onClick={createTechnician} className="w-full bg-purple-600 hover:bg-purple-700">
                      Create Technician
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </div>
          </CardHeader>
        </Card>

        {/* Technicians List */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {technicians.map((tech) => (
            <Card key={tech.id} className="bg-slate-900/50 border-slate-800 hover:border-slate-700 transition-colors">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center">
                      <UserCircle className="w-7 h-7 text-white" />
                    </div>
                    <div>
                      <CardTitle className="text-white text-lg">{tech.name}</CardTitle>
                      <div className="flex items-center gap-1 mt-1">
                        <Mail className="w-3 h-3 text-slate-500" />
                        <p className="text-xs text-slate-400">{tech.email}</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-1">
                    <Button
                      onClick={() => openEditDialog(tech)}
                      size="sm"
                      variant="ghost"
                      className="text-cyan-400 hover:text-cyan-300"
                      title="Edit"
                    >
                      <Edit className="w-4 h-4" />
                    </Button>
                    <Button
                      onClick={() => deleteTechnician(tech.id, tech.name)}
                      size="sm"
                      variant="ghost"
                      className="text-red-400 hover:text-red-300"
                      title="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-400">Role</span>
                    <Badge variant="outline" className="bg-purple-500/20 text-purple-300 border-purple-500/50">
                      <Shield className="w-3 h-3 mr-1" />
                      Technician
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-400">Created</span>
                    <span className="text-sm text-slate-300">
                      {new Date(tech.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {technicians.length === 0 && (
          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="py-12">
              <div className="text-center">
                <Users className="w-16 h-16 text-slate-700 mx-auto mb-4" />
                <p className="text-slate-400 text-lg">No technicians added yet</p>
                <p className="text-slate-500 text-sm mt-2">Click "Add Technician" to create your first technician account</p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Edit Dialog */}
        <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
          <DialogContent className="bg-slate-900 border-slate-800 text-white max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Edit className="w-5 h-5 text-cyan-400" />
                Edit Technician
              </DialogTitle>
              <DialogDescription className="text-slate-400">
                Update technician information
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 mt-4">
              <div>
                <Label className="text-white">Full Name *</Label>
                <Input
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g., John Smith"
                  className="bg-slate-800 border-slate-700 text-white mt-1"
                />
              </div>

              <div>
                <Label className="text-white">Email Address *</Label>
                <Input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  placeholder="john.smith@company.com"
                  className="bg-slate-800 border-slate-700 text-white mt-1"
                />
              </div>

              <div>
                <Label className="text-white">New Password (Optional)</Label>
                <Input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  placeholder="Leave blank to keep current password"
                  className="bg-slate-800 border-slate-700 text-white mt-1"
                />
                <p className="text-xs text-slate-500 mt-1">Only fill if you want to change the password</p>
              </div>

              <Button onClick={updateTechnician} className="w-full bg-cyan-600 hover:bg-cyan-700">
                Update Technician
              </Button>
            </div>
          </DialogContent>
        </Dialog>

        {/* Info Section */}
        <Card className="bg-slate-900/50 border-slate-800 mt-6">
          <CardHeader>
            <CardTitle className="text-white text-lg">About Technicians</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 text-sm text-slate-300">
              <div className="flex items-start gap-2">
                <span className="w-2 h-2 rounded-full bg-purple-400 mt-2"></span>
                <p><strong className="text-white">Role:</strong> Technicians can view and manage alerts and incidents assigned to them</p>
              </div>
              <div className="flex items-start gap-2">
                <span className="w-2 h-2 rounded-full bg-purple-400 mt-2"></span>
                <p><strong className="text-white">Access:</strong> They can add notes, update incident status, and mark incidents as resolved</p>
              </div>
              <div className="flex items-start gap-2">
                <span className="w-2 h-2 rounded-full bg-purple-400 mt-2"></span>
                <p><strong className="text-white">Login:</strong> Technicians use their email and password to access the system</p>
              </div>
              <div className="flex items-start gap-2">
                <span className="w-2 h-2 rounded-full bg-purple-400 mt-2"></span>
                <p><strong className="text-white">Permissions:</strong> Limited to incident management - cannot manage companies or other technicians</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Technicians;
