import React, { useState } from 'react';
import { Search, ShieldAlert, ShieldCheck, AlertCircle, Globe, Info } from 'lucide-react';
import api from '../services/api';
import { ScanResult } from '../types';
import { motion, AnimatePresence } from 'motion/react';

const PredictPage: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await api.post('/predict/', { url });
      setResult(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to analyze URL. Please check the backend connection.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto">
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold text-slate-900 mb-4 tracking-tight">URL Threat Analysis</h1>
        <p className="text-lg text-slate-500">Paste a suspicious link below to check for phishing threats using our AI model.</p>
      </div>

      <div className="bg-white p-8 rounded-3xl shadow-xl shadow-slate-200 border border-slate-100 mb-8">
        <form onSubmit={handleScan} className="space-y-6">
          <div className="relative group">
            <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
              <Globe className="h-6 w-6 text-slate-400 group-focus-within:text-blue-500 transition-colors" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example-suspicious-site.com"
              className="block w-full pl-14 pr-4 py-5 bg-slate-50 border border-slate-200 rounded-2xl text-lg focus:ring-4 focus:ring-blue-100 focus:border-blue-500 outline-none transition-all"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-700 hover:bg-blue-800 text-white font-bold py-5 rounded-2xl shadow-lg shadow-blue-200 transition-all flex items-center justify-center gap-3 disabled:opacity-50"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                Analyzing Security...
              </>
            ) : (
              <>
                <Search className="w-6 h-6" />
                Analyze URL
              </>
            )}
          </button>
        </form>
      </div>

      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="bg-red-50 border border-red-100 text-red-700 p-6 rounded-2xl flex items-center gap-4"
          >
            <AlertCircle className="w-6 h-6 shrink-0" />
            <p className="font-medium">{error}</p>
          </motion.div>
        )}

        {result && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className={`p-8 rounded-3xl border-2 shadow-2xl ${
              result.result === 'phishing' 
                ? 'bg-red-50 border-red-200 shadow-red-100' 
                : 'bg-emerald-50 border-emerald-200 shadow-emerald-100'
            }`}
          >
            <div className="flex flex-col md:flex-row items-center gap-8">
              <div className={`shrink-0 w-24 h-24 rounded-full flex items-center justify-center ${
                result.result === 'phishing' ? 'bg-red-100 text-red-600' : 'bg-emerald-100 text-emerald-600'
              }`}>
                {result.result === 'phishing' ? <ShieldAlert className="w-12 h-12" /> : <ShieldCheck className="w-12 h-12" />}
              </div>
              
              <div className="flex-1 text-center md:text-left">
                <div className="flex flex-col md:flex-row md:items-center gap-3 mb-2">
                  <h2 className={`text-3xl font-black uppercase tracking-tighter ${
                    result.result === 'phishing' ? 'text-red-700' : 'text-emerald-700'
                  }`}>
                    {result.result === 'phishing' ? 'Phishing Detected' : 'URL is Safe'}
                  </h2>
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-bold ${
                    result.result === 'phishing' ? 'bg-red-200 text-red-800' : 'bg-emerald-200 text-emerald-800'
                  }`}>
                    {Math.round(result.confidence * 100)}% Confidence
                  </span>
                </div>
                
                <p className="text-slate-700 font-medium mb-6 leading-relaxed">
                  {result.reason}
                </p>

                <div className="space-y-2">
                  <div className="flex justify-between text-xs font-bold text-slate-500 uppercase tracking-widest">
                    <span>Threat Level</span>
                    <span>{Math.round(result.confidence * 100)}%</span>
                  </div>
                  <div className="w-full bg-slate-200/50 rounded-full h-3 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${Math.round(result.confidence * 100)}%` }}
                      transition={{ duration: 1, ease: "easeOut" }}
                      className={`h-full rounded-full ${
                        result.result === 'phishing' ? 'bg-red-500' : 'bg-emerald-500'
                      }`}
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-8 pt-8 border-t border-slate-200 flex items-start gap-3 text-slate-500 text-sm italic">
              <Info className="w-4 h-4 shrink-0 mt-0.5" />
              <p>Our AI model analyzes URL patterns, domain reputation, and structural features to determine the safety of the link. Always exercise caution when clicking unknown links.</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default PredictPage;
