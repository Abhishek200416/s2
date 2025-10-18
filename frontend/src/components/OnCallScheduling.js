import React, { useState, useEffect } from 'react';
import { Calendar, Clock, User, Plus, Edit2, Trash2, Loader, CheckCircle } from 'lucide-react';
import { api as API } from '../App';

const OnCallScheduling = () => {
  const [schedules, setSchedules] = useState([]);
  const [technicians, setTechnicians] = useState([]);
  const [currentOnCall, setCurrentOnCall] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState(null);
  const [formData, setFormData] = useState({
    technician_id: '',
    schedule_type: 'daily',
    start_time: '',
    end_time: '',
    days_of_week: [],
    priority: 1
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [schedulesRes, techsRes, currentRes] = await Promise.all([
        API.get('/on-call-schedules'),
        API.get('/users'),
        API.get('/on-call-schedules/current')
      ]);
      setSchedules(schedulesRes.data);
      setTechnicians(techsRes.data.filter(u => u.role === 'technician' || u.role === 'admin'));
      setCurrentOnCall(currentRes.data);
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (editingSchedule) {
        await API.put(`/on-call-schedules/${editingSchedule.id}`, formData);
      } else {
        await API.post('/on-call-schedules', formData);
      }
      await loadData();
      resetForm();
      alert(`Schedule ${editingSchedule ? 'updated' : 'created'} successfully!`);
    } catch (error) {
      alert('Failed to save schedule: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this schedule?')) return;
    setLoading(true);
    try {
      await API.delete(`/on-call-schedules/${id}`);
      await loadData();
      alert('Schedule deleted successfully');
    } catch (error) {
      alert('Failed to delete schedule: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (schedule) => {
    setEditingSchedule(schedule);
    setFormData({
      technician_id: schedule.technician_id,
      schedule_type: schedule.schedule_type,
      start_time: schedule.start_time,
      end_time: schedule.end_time,
      days_of_week: schedule.days_of_week || [],
      priority: schedule.priority || 1
    });
    setShowForm(true);
  };

  const resetForm = () => {
    setFormData({
      technician_id: '',
      schedule_type: 'daily',
      start_time: '',
      end_time: '',
      days_of_week: [],
      priority: 1
    });
    setEditingSchedule(null);
    setShowForm(false);
  };

  const getTechnicianName = (id) => {
    const tech = technicians.find(t => t.id === id);
    return tech ? tech.name : 'Unknown';
  };

  const formatTime = (time) => {
    if (!time) return '';
    const date = new Date(time);
    return date.toLocaleString();
  };

  const daysOfWeekOptions = [
    { value: 0, label: 'Monday' },
    { value: 1, label: 'Tuesday' },
    { value: 2, label: 'Wednesday' },
    { value: 3, label: 'Thursday' },
    { value: 4, label: 'Friday' },
    { value: 5, label: 'Saturday' },
    { value: 6, label: 'Sunday' }
  ];

  return (
    <div className="space-y-6">
      {/* Current On-Call Card */}
      {currentOnCall && (
        <div className="bg-gradient-to-r from-cyan-600 to-blue-600 rounded-lg p-6 border border-cyan-500">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="bg-white/20 p-3 rounded-full">
                <User className="w-8 h-8 text-white" />
              </div>
              <div>
                <p className="text-sm text-cyan-100">Currently On-Call</p>
                <h3 className="text-2xl font-bold text-white">{getTechnicianName(currentOnCall.technician_id)}</h3>
                <p className="text-sm text-cyan-100 mt-1">
                  {currentOnCall.schedule_type === 'one_time' ? 'One-Time Shift' : 
                   currentOnCall.schedule_type === 'daily' ? 'Daily Shift' : 'Weekly Shift'}
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-6 h-6 text-green-300" />
              <span className="text-white font-medium">Active</span>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">On-Call Scheduling</h2>
          <p className="text-gray-400 mt-1">Manage MSP-wide on-call schedules for incident auto-assignment</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>Create Schedule</span>
        </button>
      </div>

      {/* Create/Edit Form */}
      {showForm && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-white mb-4">
            {editingSchedule ? 'Edit Schedule' : 'Create New Schedule'}
          </h3>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Technician</label>
              <select
                value={formData.technician_id}
                onChange={(e) => setFormData({ ...formData, technician_id: e.target.value })}
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="">Select technician</option>
                {technicians.map(tech => (
                  <option key={tech.id} value={tech.id}>{tech.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Schedule Type</label>
              <select
                value={formData.schedule_type}
                onChange={(e) => setFormData({ ...formData, schedule_type: e.target.value })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="one_time">One-Time (Specific date/time)</option>
                <option value="daily">Daily (Same time every day)</option>
                <option value="weekly">Weekly (Specific days of week)</option>
              </select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Start Time</label>
                <input
                  type="datetime-local"
                  value={formData.start_time}
                  onChange={(e) => setFormData({ ...formData, start_time: e.target.value })}
                  required
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">End Time</label>
                <input
                  type="datetime-local"
                  value={formData.end_time}
                  onChange={(e) => setFormData({ ...formData, end_time: e.target.value })}
                  required
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {formData.schedule_type === 'weekly' && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Days of Week</label>
                <div className="grid grid-cols-4 gap-2">
                  {daysOfWeekOptions.map(day => (
                    <label key={day.value} className="flex items-center space-x-2 text-gray-300">
                      <input
                        type="checkbox"
                        checked={formData.days_of_week.includes(day.value)}
                        onChange={(e) => {
                          const days = e.target.checked
                            ? [...formData.days_of_week, day.value]
                            : formData.days_of_week.filter(d => d !== day.value);
                          setFormData({ ...formData, days_of_week: days });
                        }}
                        className="rounded bg-gray-700 border-gray-600 text-cyan-600 focus:ring-cyan-500"
                      />
                      <span className="text-sm">{day.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Priority (Higher = Takes precedence in conflicts)
              </label>
              <input
                type="number"
                min="1"
                max="10"
                value={formData.priority}
                onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex space-x-3">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {loading ? (
                  <Loader className="w-4 h-4 animate-spin" />
                ) : (
                  <CheckCircle className="w-4 h-4" />
                )}
                <span>{loading ? 'Saving...' : editingSchedule ? 'Update Schedule' : 'Create Schedule'}</span>
              </button>
              <button
                type="button"
                onClick={resetForm}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Schedules List */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">All Schedules</h3>
        {loading && schedules.length === 0 ? (
          <div className="flex items-center justify-center py-8">
            <Loader className="w-6 h-6 animate-spin text-cyan-400" />
          </div>
        ) : schedules.length === 0 ? (
          <div className="text-center py-8">
            <Calendar className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">No schedules created yet</p>
          </div>
        ) : (
          <div className="space-y-3">
            {schedules.map(schedule => (
              <div key={schedule.id} className="bg-gray-700/50 rounded-lg p-4 border border-gray-600">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <User className="w-5 h-5 text-cyan-400" />
                      <span className="font-medium text-white">{getTechnicianName(schedule.technician_id)}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        schedule.schedule_type === 'one_time' ? 'bg-purple-500/20 text-purple-300' :
                        schedule.schedule_type === 'daily' ? 'bg-green-500/20 text-green-300' :
                        'bg-blue-500/20 text-blue-300'
                      }`}>
                        {schedule.schedule_type === 'one_time' ? 'One-Time' :
                         schedule.schedule_type === 'daily' ? 'Daily' : 'Weekly'}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div className="flex items-center space-x-2 text-gray-400">
                        <Clock className="w-4 h-4" />
                        <span>Start: {formatTime(schedule.start_time)}</span>
                      </div>
                      <div className="flex items-center space-x-2 text-gray-400">
                        <Clock className="w-4 h-4" />
                        <span>End: {formatTime(schedule.end_time)}</span>
                      </div>
                    </div>
                    {schedule.schedule_type === 'weekly' && schedule.days_of_week?.length > 0 && (
                      <div className="mt-2 text-sm text-gray-400">
                        Days: {schedule.days_of_week.map(d => daysOfWeekOptions[d]?.label).join(', ')}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => handleEdit(schedule)}
                      className="p-2 bg-gray-600 hover:bg-gray-500 text-white rounded-lg transition-colors"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDelete(schedule.id)}
                      disabled={loading}
                      className="p-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors disabled:opacity-50"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default OnCallScheduling;