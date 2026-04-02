import React, { useState, useEffect } from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, AreaChart, Area
} from 'recharts';
import { Activity, ShieldCheck, Clock, Zap, AlertTriangle, Bug } from 'lucide-react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

const COLORS = ['#10b981', '#f43f5e', '#6366f1', '#f59e0b', '#8b5cf6'];
const PIE_COLORS = { true_positives: '#10b981', false_positives: '#f43f5e', missed: '#64748b' };

export default function MetricsShowcase() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get(`${API_BASE_URL}/metrics/showcase`)
      .then(res => {
        setData(res.data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Failed to load metrics", err);
        setError("Failed to load batch report. Ensure the background ingestion script has finished or check backend connection.");
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-24 space-y-4">
        <div className="w-8 h-8 rounded-full border-2 border-indigo-500 border-t-transparent animate-spin"></div>
        <p className="text-slate-400 font-mono text-sm animate-pulse">Loading Batch Telemetry...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-8 border border-red-500/20 bg-red-500/10 rounded-xl text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
        <p className="text-red-300 font-medium">{error || "No data available."}</p>
        <p className="text-sm text-red-400/70 mt-2">Run the batch ingestion script before accessing this dashboard.</p>
      </div>
    );
  }

  const { summary_metrics: summary, detailed_reports: reports } = data;

  // Derived metrics
  const tpr = ((summary.true_positives / summary.total_known_vulns) * 100).toFixed(1);
  const psr = summary.true_positives ? ((summary.successful_patches / summary.true_positives) * 100).toFixed(1) : 0;
  const avgMttr = (summary.total_mttr_seconds / summary.total_cases).toFixed(2);
  const avgTokens = Math.round(summary.total_tokens_used / summary.total_cases);
  
  // Data for PieChart (TPR vs FPR logic)
  // We'll show True Positives vs False Positives visually
  const detectionData = [
    { name: 'True Positives', value: summary.true_positives, color: PIE_COLORS.true_positives },
    { name: 'False Positives', value: summary.false_positives, color: PIE_COLORS.false_positives }
  ];

  // Data for Verification Rigor
  const verificationData = [
    {
      name: 'Adversarial Tests',
      Passed: summary.adversarial_tests_passed,
      Failed: summary.total_adversarial_tests - summary.adversarial_tests_passed,
    },
    {
      name: 'Functional Tests',
      Passed: summary.functional_tests_passed,
      Failed: summary.total_functional_tests - summary.functional_tests_passed,
    }
  ];

  // Map charts for trajectory over cases
  const timelineData = reports.map((report, idx) => ({
    name: `Case ${idx+1}`,
    cve: report.cve,
    mttr: report.mttr_sec,
    patched: report.verification_status === "PASS" ? 1 : 0
  }));

  const StatCard = ({ title, value, subtext, icon: Icon, colorClass }) => (
    <div className="p-5 bg-[#0f1117] border border-white/5 rounded-xl shadow-[0_4px_20px_rgba(0,0,0,0.2)]">
      <div className="flex justify-between items-start mb-2">
        <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</h3>
        <div className={`p-1.5 rounded-lg ${colorClass}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="text-3xl font-bold tracking-tight text-white">{value}</div>
      <div className="text-xs text-slate-500 mt-2 font-mono">{subtext}</div>
    </div>
  );

  return (
    <div className="space-y-6">
      
      {/* Top Status Bar */}
      <div className="flex items-center justify-between p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
        <div className="flex items-center gap-3 text-emerald-400">
           <ShieldCheck className="w-5 h-5" />
           <span className="font-semibold tracking-wide">BATCH PIPELINE VALIDATED</span>
        </div>
        <div className="text-sm text-emerald-400/80 font-mono">
           {summary.total_cases} CASES PROCESSED
        </div>
      </div>

      {/* High-Level Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          title="Patch Success Rate" 
          value={`${psr}%`} 
          subtext={`${summary.successful_patches} of ${summary.true_positives} vulnerabilities fixed`}
          icon={ShieldCheck} 
          colorClass="bg-emerald-500/20 text-emerald-400"
        />
        <StatCard 
          title="Recall (TPR)" 
          value={`${tpr}%`} 
          subtext={`${summary.true_positives} of ${summary.total_known_vulns} known flaws found`}
          icon={Activity} 
          colorClass="bg-blue-500/20 text-blue-400"
        />
        <StatCard 
          title="Avg MTTR" 
          value={`${avgMttr}s`} 
          subtext="Mean Time to Remediate per case"
          icon={Clock} 
          colorClass="bg-purple-500/20 text-purple-400"
        />
        <StatCard 
          title="Token Efficiency" 
          value={avgTokens} 
          subtext="LLM tokens used per patch sequence"
          icon={Zap} 
          colorClass="bg-amber-500/20 text-amber-400"
        />
      </div>

      {/* Main Charts Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Trajectory Area Chart */}
        <div className="lg:col-span-2 p-6 bg-[#0f1117] border border-white/5 rounded-xl">
           <div className="mb-6">
             <h3 className="text-sm font-semibold text-slate-200">Remediation Speed Over Time (MTTR)</h3>
             <p className="text-xs text-slate-500 mt-1">Seconds taken to fully analyze, patch, and verify each case.</p>
           </div>
           <div className="h-64">
             <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="colorMttr" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                  <XAxis dataKey="name" stroke="#4b5563" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="#4b5563" fontSize={12} tickLine={false} axisLine={false} />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px' }}
                    itemStyle={{ color: '#e5e7eb' }}
                  />
                  <Area type="monotone" dataKey="mttr" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#colorMttr)" name="MTTR (seconds)" />
                </AreaChart>
             </ResponsiveContainer>
           </div>
        </div>

        {/* Verification Rigor Stacked Bar */}
        <div className="p-6 bg-[#0f1117] border border-white/5 rounded-xl flex flex-col">
           <div className="mb-4">
             <h3 className="text-sm font-semibold text-slate-200">Verification Rigor</h3>
             <p className="text-xs text-slate-500 mt-1">Automated test harness results</p>
           </div>
           <div className="flex-1 min-h-[220px]">
             <ResponsiveContainer width="100%" height="100%">
               <BarChart data={verificationData} layout="vertical" margin={{ top: 0, right: 30, left: 30, bottom: 0 }}>
                 <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
                 <XAxis type="number" stroke="#4b5563" fontSize={11} />
                 <YAxis dataKey="name" type="category" stroke="#9ca3af" fontSize={12} tickLine={false} axisLine={false} width={100} />
                 <RechartsTooltip 
                    cursor={{fill: '#1f2937'}}
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px' }}
                 />
                 <Legend wrapperStyle={{ fontSize: '12px', marginTop: '10px' }}/>
                 <Bar dataKey="Passed" stackId="a" fill="#10b981" radius={[0, 0, 0, 0]} />
                 <Bar dataKey="Failed" stackId="a" fill="#f43f5e" radius={[0, 4, 4, 0]} />
               </BarChart>
             </ResponsiveContainer>
           </div>
        </div>

      </div>

      {/* Bottom Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Detection Accuracy Donut */}
        <div className="p-6 bg-[#0f1117] border border-white/5 rounded-xl flex flex-col items-center text-center">
           <h3 className="text-sm font-semibold text-slate-200 w-full text-left">Detection Accuracy</h3>
           <p className="text-xs text-slate-500 mt-1 w-full text-left mb-4">True Positives vs Dev Noise (FPR)</p>
           
           <div className="h-48 w-full flex-1">
             <ResponsiveContainer width="100%" height="100%">
               <PieChart>
                 <Pie
                   data={detectionData}
                   cx="50%"
                   cy="50%"
                   innerRadius={60}
                   outerRadius={80}
                   paddingAngle={5}
                   dataKey="value"
                   stroke="none"
                 >
                   {detectionData.map((entry, index) => (
                     <Cell key={`cell-${index}`} fill={entry.color} />
                   ))}
                 </Pie>
                 <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px', padding: '8px' }}
                    itemStyle={{ color: '#e5e7eb', fontSize: '14px' }}
                 />
               </PieChart>
             </ResponsiveContainer>
           </div>
           <div className="w-full flex justify-between px-6 mt-2">
             <div className="text-center">
               <div className="text-2xl font-bold text-emerald-400">{summary.true_positives}</div>
               <div className="text-[10px] text-slate-400 uppercase">Exploitable</div>
             </div>
             <div className="text-center">
               <div className="text-2xl font-bold text-rose-400">{summary.false_positives}</div>
               <div className="text-[10px] text-slate-400 uppercase">False Flags</div>
             </div>
           </div>
        </div>

        {/* Detailed List */}
        <div className="lg:col-span-2 p-6 bg-[#0f1117] border border-white/5 rounded-xl">
           <div className="flex justify-between items-center mb-6">
             <div>
               <h3 className="text-sm font-semibold text-slate-200">Execution Log</h3>
               <p className="text-xs text-slate-500 mt-1">Detailed results of the batch pipeline</p>
             </div>
             <div className="text-xs font-mono text-slate-400 bg-white/5 px-2 py-1 rounded">Regressions: <span className={summary.regressions_caused > 0 ? "text-rose-400" : "text-emerald-400"}>{summary.regressions_caused}</span></div>
           </div>
           
           <div className="overflow-y-auto h-56 pr-2 custom-scrollbar">
             <table className="w-full text-sm text-left">
               <thead className="text-xs text-slate-500 uppercase bg-white/5 sticky top-0">
                 <tr>
                   <th className="px-4 py-3 font-medium rounded-l-lg">CVE ID</th>
                   <th className="px-4 py-3 font-medium">Ground Truth</th>
                   <th className="px-4 py-3 font-medium border-l border-white/5 text-center">Regression</th>
                   <th className="px-4 py-3 font-medium text-center text-emerald-500">Security</th>
                   <th className="px-4 py-3 font-medium text-right rounded-r-lg">Actions</th>
                 </tr>
               </thead>
               <tbody>
                 {reports.map((report, idx) => (
                   <tr key={idx} className="border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition-colors">
                     <td className="px-4 py-3 font-mono text-slate-300">{report.cve}</td>
                     <td className="px-4 py-3 text-slate-400">
                        <span className="inline-block px-2 py-0.5 rounded bg-slate-800 text-xs shadow-sm border border-slate-700/50">
                          {report.ground_truth}
                        </span>
                     </td>
                     <td className="px-4 py-3 border-l border-white/5">
                        <div className="flex justify-center">
                          {report.regression_passed === true ? (
                            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]" title="Passed"></div>
                          ) : report.regression_passed === false ? (
                            <div className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.4)]" title="Failed"></div>
                          ) : (
                            <div className="w-2 h-2 rounded-full bg-slate-600" title="Not Run"></div>
                          )}
                        </div>
                     </td>
                     <td className="px-4 py-3">
                        <div className="flex justify-center">
                          {report.security_passed === true ? (
                            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]" title="Passed"></div>
                          ) : report.security_passed === false ? (
                            <div className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.4)]" title="Failed"></div>
                          ) : (
                            <div className="w-2 h-2 rounded-full bg-slate-600" title="Not Run"></div>
                          )}
                        </div>
                     </td>
                     <td className="px-4 py-3 text-right">
                       <span className={`text-xs px-2 py-1 rounded font-medium ${report.verification_status === "PASS" ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"}`}>
                         {report.verification_status}
                       </span>
                     </td>
                   </tr>
                 ))}
               </tbody>
             </table>
           </div>
           
        </div>
      </div>
    </div>
  );
}
