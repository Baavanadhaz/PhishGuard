import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { ShieldAlert, ShieldCheck, Activity, Percent, ArrowRight } from 'lucide-react';
import api from '../services/api';
import { ScanResult, DashboardStats } from '../types';
import LoadingSpinner from '../components/LoadingSpinner';
import { motion } from 'motion/react';
import { Link } from 'react-router-dom';

const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await api.get('/history/');
        const history: ScanResult[] = response.data;
        
        const phishing = history.filter(s => s.result === 'phishing').length;
        const safe = history.filter(s => s.result === 'safe').length;
        const total = history.length;
        
        setStats({
          total_scans: total,
          phishing_count: phishing,
          safe_count: safe,
          phishing_percentage: total > 0 ? (phishing / total) * 100 : 0
        });
        
        setRecentScans(history.slice(0, 5));
      } catch (err) {
        setError('Failed to load dashboard data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) return <LoadingSpinner />;

  const chartData = [
    { name: 'Safe', value: stats?.safe_count || 0 },
    { name: 'Phishing', value: stats?.phishing_count || 0 },
  ];

  const COLORS = ['#10b981', '#ef4444'];

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-8"
    >
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Security Overview</h1>
          <p className="text-slate-500">Monitor your URL scanning activity and threat levels</p>
        </div>
        <Link 
          to="/predict"
          className="inline-flex items-center gap-2 bg-blue-700 text-white px-6 py-3 rounded-xl font-semibold shadow-lg shadow-blue-200 hover:bg-blue-800 transition-all"
        >
          Scan New URL
          <ArrowRight className="w-4 h-4" />
        </Link>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-100 text-red-700 p-4 rounded-xl">
          {error}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {[
          { label: 'Total Scans', value: stats?.total_scans, icon: Activity, color: 'text-blue-600', bg: 'bg-blue-50' },
          { label: 'Phishing Detected', value: stats?.phishing_count, icon: ShieldAlert, color: 'text-red-600', bg: 'bg-red-50' },
          { label: 'Safe URLs', value: stats?.safe_count, icon: ShieldCheck, color: 'text-emerald-600', bg: 'bg-emerald-50' },
          { label: 'Phishing Rate', value: `${stats?.phishing_percentage.toFixed(1)}%`, icon: Percent, color: 'text-amber-600', bg: 'bg-amber-50' },
        ].map((stat, idx) => (
          <div key={idx} className="bg-white p-6 rounded-2xl border border-slate-100 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div className={`${stat.bg} ${stat.color} p-3 rounded-xl`}>
                <stat.icon className="w-6 h-6" />
              </div>
            </div>
            <p className="text-sm font-medium text-slate-500 uppercase tracking-wider">{stat.label}</p>
            <h3 className="text-2xl font-bold text-slate-900 mt-1">{stat.value}</h3>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Chart Card */}
        <div className="lg:col-span-1 bg-white p-8 rounded-2xl border border-slate-100 shadow-sm">
          <h2 className="text-lg font-bold text-slate-900 mb-6">Threat Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 10px 15px -3px rgba(0,0,0,0.1)' }}
                />
                <Legend verticalAlign="bottom" height={36}/>
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Scans Table */}
        <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
          <div className="p-8 border-b border-slate-100 flex items-center justify-between">
            <h2 className="text-lg font-bold text-slate-900">Recent Scans</h2>
            <Link to="/history" className="text-blue-600 text-sm font-semibold hover:underline">View All</Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-slate-50/50">
                  <th className="px-8 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">URL</th>
                  <th className="px-8 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Result</th>
                  <th className="px-8 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {recentScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-8 py-4">
                      <div className="max-w-xs truncate text-sm font-medium text-slate-700" title={scan.url}>
                        {scan.url}
                      </div>
                    </td>
                    <td className="px-8 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        scan.result === 'phishing' ? 'bg-red-100 text-red-700' : 'bg-emerald-100 text-emerald-700'
                      }`}>
                        {scan.result.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-8 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-slate-100 rounded-full h-1.5 overflow-hidden">
                          <div 
                            className={`h-full rounded-full ${scan.result === 'phishing' ? 'bg-red-500' : 'bg-emerald-500'}`}
                            style={{ width: `${scan.confidence}%` }}
                          />
                        </div>
                        <span className="text-xs font-semibold text-slate-600">{scan.confidence.toFixed(0)}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
                {recentScans.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-8 py-12 text-center text-slate-500">
                      No scans performed yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default DashboardPage;
