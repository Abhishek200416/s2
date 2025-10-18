import React from 'react';
import { ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import OnCallScheduling from '../components/OnCallScheduling';

const OnCallSchedule = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center space-x-2 text-gray-400 hover:text-white transition-colors mb-4"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Dashboard</span>
          </button>
          <h1 className="text-3xl font-bold text-white">On-Call Schedule Management</h1>
          <p className="text-gray-400 mt-2">
            Manage MSP-wide on-call schedules for automated incident assignment
          </p>
        </div>

        {/* On-Call Scheduling Component */}
        <OnCallScheduling />
      </div>
    </div>
  );
};

export default OnCallSchedule;
