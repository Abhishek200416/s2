import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { User, Lock, Mail, Save, X } from 'lucide-react';
import { toast } from 'sonner';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

const Profile = ({ user, onLogout, onUpdate }) => {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(user.name);
  const [email, setEmail] = useState(user.email);
  const [updating, setUpdating] = useState(false);

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);

  useEffect(() => {
    setName(user.name);
    setEmail(user.email);
  }, [user]);

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setUpdating(true);

    try {
      const response = await api.put('/profile', { name, email });
      toast.success('Profile updated successfully');
      setEditing(false);
      
      // Update user in local storage
      const updatedUser = response.data;
      localStorage.setItem('user', JSON.stringify(updatedUser));
      
      // Call parent update callback
      if (onUpdate) {
        onUpdate(updatedUser);
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update profile');
    } finally {
      setUpdating(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();

    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match');
      return;
    }

    if (newPassword.length < 6) {
      toast.error('Password must be at least 6 characters');
      return;
    }

    setChangingPassword(true);

    try {
      await api.put('/profile/password', {
        current_password: currentPassword,
        new_password: newPassword
      });
      
      toast.success('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to change password');
    } finally {
      setChangingPassword(false);
    }
  };

  const handleCancel = () => {
    setEditing(false);
    setName(user.name);
    setEmail(user.email);
  };

  return (
    <div className="min-h-screen bg-slate-950 py-8">
      <div className="max-w-4xl mx-auto px-6">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-white mb-2">Profile Settings</h1>
          <p className="text-slate-400">Manage your account information and security</p>
        </div>

        <Tabs defaultValue="profile" className="space-y-6">
          <TabsList className="bg-slate-900/50 border border-slate-800">
            <TabsTrigger 
              value="profile"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <User className="w-4 h-4 mr-2" />
              Profile Information
            </TabsTrigger>
            <TabsTrigger 
              value="security"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Lock className="w-4 h-4 mr-2" />
              Security
            </TabsTrigger>
          </TabsList>

          {/* Profile Information Tab */}
          <TabsContent value="profile">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">Profile Information</CardTitle>
                <CardDescription className="text-slate-400">
                  Update your personal information
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleUpdateProfile} className="space-y-6">
                  {/* User Info Display */}
                  <div className="flex items-center gap-4 p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="w-16 h-16 bg-cyan-500/20 rounded-full flex items-center justify-center border-2 border-cyan-500/30">
                      <User className="w-8 h-8 text-cyan-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">{user.name}</h3>
                      <p className="text-sm text-slate-400">{user.email}</p>
                      <span className="inline-block px-2 py-1 mt-1 text-xs rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                        {user.role}
                      </span>
                    </div>
                  </div>

                  {/* Edit Form */}
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="name" className="text-slate-300">Full Name</Label>
                      <Input
                        id="name"
                        type="text"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        disabled={!editing}
                        required
                        className={`bg-slate-800/50 border-slate-700 text-white ${!editing ? 'opacity-60' : ''}`}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="email" className="text-slate-300">
                        <Mail className="w-4 h-4 inline mr-2" />
                        Email Address
                      </Label>
                      <Input
                        id="email"
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        disabled={!editing}
                        required
                        className={`bg-slate-800/50 border-slate-700 text-white ${!editing ? 'opacity-60' : ''}`}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label className="text-slate-300">Role</Label>
                      <Input
                        type="text"
                        value={user.role}
                        disabled
                        className="bg-slate-800/30 border-slate-700 text-slate-400 opacity-60"
                      />
                      <p className="text-xs text-slate-500">Role cannot be changed</p>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-3 pt-4 border-t border-slate-800">
                    {!editing ? (
                      <Button
                        type="button"
                        onClick={() => setEditing(true)}
                        className="bg-cyan-600 hover:bg-cyan-700 text-white"
                      >
                        <User className="w-4 h-4 mr-2" />
                        Edit Profile
                      </Button>
                    ) : (
                      <>
                        <Button
                          type="submit"
                          disabled={updating}
                          className="bg-cyan-600 hover:bg-cyan-700 text-white"
                        >
                          <Save className="w-4 h-4 mr-2" />
                          {updating ? 'Saving...' : 'Save Changes'}
                        </Button>
                        <Button
                          type="button"
                          onClick={handleCancel}
                          variant="outline"
                          className="border-slate-700 text-slate-300 hover:bg-slate-800"
                        >
                          <X className="w-4 h-4 mr-2" />
                          Cancel
                        </Button>
                      </>
                    )}
                  </div>
                </form>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Security Tab */}
          <TabsContent value="security">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">Change Password</CardTitle>
                <CardDescription className="text-slate-400">
                  Update your password to keep your account secure
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleChangePassword} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="current-password" className="text-slate-300">
                      Current Password
                    </Label>
                    <Input
                      id="current-password"
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      required
                      className="bg-slate-800/50 border-slate-700 text-white"
                      placeholder="Enter current password"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="new-password" className="text-slate-300">
                      New Password
                    </Label>
                    <Input
                      id="new-password"
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      required
                      className="bg-slate-800/50 border-slate-700 text-white"
                      placeholder="Enter new password"
                      minLength={6}
                    />
                    <p className="text-xs text-slate-500">Minimum 6 characters</p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="confirm-password" className="text-slate-300">
                      Confirm New Password
                    </Label>
                    <Input
                      id="confirm-password"
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                      className="bg-slate-800/50 border-slate-700 text-white"
                      placeholder="Confirm new password"
                      minLength={6}
                    />
                  </div>

                  <div className="pt-4 border-t border-slate-800">
                    <Button
                      type="submit"
                      disabled={changingPassword}
                      className="bg-cyan-600 hover:bg-cyan-700 text-white"
                    >
                      <Lock className="w-4 h-4 mr-2" />
                      {changingPassword ? 'Changing Password...' : 'Change Password'}
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Profile;
