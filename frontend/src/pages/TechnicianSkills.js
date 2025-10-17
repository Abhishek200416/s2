import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_BACKEND_URL || '';

function TechnicianSkills() {
  const [technicians, setTechnicians] = useState([]);
  const [selectedTech, setSelectedTech] = useState(null);
  const [loading, setLoading] = useState(true);
  const [editModal, setEditModal] = useState(false);
  
  // Edit form state
  const [editSkills, setEditSkills] = useState([]);
  const [newSkill, setNewSkill] = useState('');
  const [workloadMax, setWorkloadMax] = useState(10);
  const [availability, setAvailability] = useState('available');
  const [saving, setSaving] = useState(false);

  const allSkills = [
    'linux', 'windows', 'database', 'network', 'application', 
    'security', 'cloud_aws', 'cloud_azure', 'docker', 'kubernetes'
  ];

  useEffect(() => {
    fetchTechnicians();
  }, []);

  const fetchTechnicians = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_URL}/users`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const techUsers = response.data.filter(u => 
        u.role === 'technician' || u.role === 'company_admin'
      );
      
      // Fetch skills for each technician
      const techWithSkills = await Promise.all(
        techUsers.map(async (tech) => {
          try {
            const skillsRes = await axios.get(
              `${API_URL}/msp/technicians/${tech.id}/skills`,
              { headers: { Authorization: `Bearer ${token}` } }
            );
            return { ...tech, skills: skillsRes.data };
          } catch (error) {
            return { ...tech, skills: null };
          }
        })
      );
      
      setTechnicians(techWithSkills);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching technicians:', error);
      setLoading(false);
    }
  };

  const openEditModal = (tech) => {
    setSelectedTech(tech);
    setEditSkills(tech.skills?.skills || []);
    setWorkloadMax(tech.skills?.workload_max || 10);
    setAvailability(tech.skills?.availability || 'available');
    setEditModal(true);
  };

  const addSkill = () => {
    if (newSkill && !editSkills.includes(newSkill)) {
      setEditSkills([...editSkills, newSkill]);
      setNewSkill('');
    }
  };

  const removeSkill = (skill) => {
    setEditSkills(editSkills.filter(s => s !== skill));
  };

  const saveSkills = async () => {
    setSaving(true);
    try {
      const token = localStorage.getItem('token');
      await axios.put(
        `${API_URL}/msp/technicians/${selectedTech.id}/skills`,
        {
          skills: editSkills,
          workload_max: workloadMax,
          availability: availability
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      
      setEditModal(false);
      fetchTechnicians();
    } catch (error) {
      console.error('Error saving skills:', error);
      alert('Failed to save skills: ' + (error.response?.data?.detail || error.message));
    } finally {
      setSaving(false);
    }
  };

  const getAvailabilityBadge = (status) => {
    switch(status) {
      case 'available':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'busy':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'offline':
        return 'bg-gray-100 text-gray-800 border-gray-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getWorkloadColor = (current, max) => {
    const percentage = (current / max) * 100;
    if (percentage >= 90) return 'text-red-400';
    if (percentage >= 70) return 'text-yellow-400';
    return 'text-green-400';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading technicians...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">👥 Technician Skills Management</h1>
            <p className="text-slate-400">Manage technician skills, workload, and availability</p>
          </div>
          <button
            onClick={() => window.location.href = '/dashboard'}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
          >
            ← Back to Dashboard
          </button>
        </div>
      </div>

      {/* Info Card */}
      <div className="bg-blue-900 border border-blue-700 rounded-lg p-4 mb-6">
        <h3 className="text-blue-300 font-semibold mb-2">💡 Auto-Assignment Features</h3>
        <p className="text-blue-200 text-sm">
          Technician skills are used for intelligent auto-assignment. The system matches incident requirements with technician expertise, considers current workload, and respects availability status for optimal distribution.
        </p>
      </div>

      {/* Technicians Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {technicians.map(tech => (
          <div
            key={tech.id}
            className="bg-slate-800 border border-slate-700 rounded-lg p-6 hover:border-cyan-500 transition-all"
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-white">{tech.name}</h3>
                <p className="text-sm text-slate-400">{tech.email}</p>
                <span className="inline-block mt-2 px-2 py-1 text-xs bg-slate-700 text-slate-300 rounded">
                  {tech.role}
                </span>
              </div>
            </div>

            {/* Availability */}
            <div className="mb-4">
              <span className={`px-3 py-1 text-xs font-medium rounded-full border ${
                getAvailabilityBadge(tech.skills?.availability || 'available')
              }`}>
                {(tech.skills?.availability || 'available').toUpperCase()}
              </span>
            </div>

            {/* Workload */}
            <div className="mb-4 p-3 bg-slate-900 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-400 text-sm">Current Workload</span>
                <span className={`text-lg font-bold ${
                  getWorkloadColor(tech.skills?.workload_current || 0, tech.skills?.workload_max || 10)
                }`}>
                  {tech.skills?.workload_current || 0} / {tech.skills?.workload_max || 10}
                </span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all"
                  style={{
                    width: `${Math.min(((tech.skills?.workload_current || 0) / (tech.skills?.workload_max || 10)) * 100, 100)}%`
                  }}
                />
              </div>
            </div>

            {/* Skills */}
            <div className="mb-4">
              <h4 className="text-slate-300 text-sm font-medium mb-2">Skills</h4>
              {tech.skills?.skills && tech.skills.skills.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {tech.skills.skills.map(skill => (
                    <span
                      key={skill}
                      className="px-2 py-1 text-xs bg-cyan-900 text-cyan-300 rounded border border-cyan-700"
                    >
                      {skill}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 text-sm">No skills assigned</p>
              )}
            </div>

            {/* Action Button */}
            <button
              onClick={() => openEditModal(tech)}
              className="w-full px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-lg font-semibold hover:from-cyan-500 hover:to-blue-500 transition-all"
            >
              ✏️ Edit Skills & Workload
            </button>
          </div>
        ))}
      </div>

      {technicians.length === 0 && (
        <div className="text-center py-12">
          <p className="text-slate-400 text-lg">No technicians found</p>
          <p className="text-slate-500 text-sm mt-2">Add technicians from the Technicians management page</p>
        </div>
      )}

      {/* Edit Modal */}
      {editModal && selectedTech && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-slate-800 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto border border-slate-700">
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold text-white">Edit Technician Skills</h2>
                  <p className="text-slate-400 mt-1">{selectedTech.name}</p>
                </div>
                <button
                  onClick={() => setEditModal(false)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-6">
              {/* Skills Selection */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Skills</label>
                <div className="flex space-x-2 mb-3">
                  <select
                    value={newSkill}
                    onChange={(e) => setNewSkill(e.target.value)}
                    className="flex-1 px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="">Select a skill</option>
                    {allSkills.filter(s => !editSkills.includes(s)).map(skill => (
                      <option key={skill} value={skill}>{skill}</option>
                    ))}
                  </select>
                  <button
                    onClick={addSkill}
                    disabled={!newSkill}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    + Add
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {editSkills.map(skill => (
                    <span
                      key={skill}
                      className="px-3 py-1 bg-cyan-900 text-cyan-300 rounded-lg border border-cyan-700 flex items-center space-x-2"
                    >
                      <span>{skill}</span>
                      <button
                        onClick={() => removeSkill(skill)}
                        className="text-cyan-400 hover:text-cyan-200"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              </div>

              {/* Workload Max */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Max Concurrent Incidents
                </label>
                <input
                  type="number"
                  min="1"
                  max="50"
                  value={workloadMax}
                  onChange={(e) => setWorkloadMax(parseInt(e.target.value))}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                />
                <p className="text-xs text-slate-400 mt-1">
                  Maximum number of incidents this technician can handle at once
                </p>
              </div>

              {/* Availability */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Availability Status</label>
                <select
                  value={availability}
                  onChange={(e) => setAvailability(e.target.value)}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="available">Available</option>
                  <option value="busy">Busy</option>
                  <option value="offline">Offline</option>
                </select>
              </div>

              {/* Action Buttons */}
              <div className="flex space-x-4">
                <button
                  onClick={saveSkills}
                  disabled={saving}
                  className="flex-1 px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-lg font-semibold hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {saving ? 'Saving...' : '💾 Save Changes'}
                </button>
                <button
                  onClick={() => setEditModal(false)}
                  className="px-6 py-3 bg-slate-700 text-white rounded-lg font-semibold hover:bg-slate-600 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default TechnicianSkills;
