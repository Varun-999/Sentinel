import React, { useState, useEffect } from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, AreaChart, Area
} from 'recharts';
import { Activity, ShieldCheck, Clock, Zap, AlertTriangle, Bug, Info, ListTree, TestTube, Crosshair, BarChart2, X } from 'lucide-react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

const COLORS = ['#10b981', '#f43f5e', '#6366f1', '#f59e0b', '#8b5cf6'];
const PIE_COLORS = { true_positives: '#10b981', false_positives: '#f43f5e', missed: '#64748b' };

const PANEL_INFO = {
  'psr': "Patch Success Rate (PSR) measures the percentage of correctly identified true positive vulnerabilities that the Blue Agent successfully mitigated. A patch is considered successful only if it wholly blocks the adversarial payload (Security Verification) whilst simultaneously preserving all expected end-user functionality and preventing regressions (Functional Verification). It is the ultimate indicator of autonomous remediation efficacy.",
  'tpr': "True Positive Rate (Recall) isolates the Red Agent's detection capability against known embedded ground-truth vulnerabilities inside the dataset. A high TPR indicates that the system is aggressively catching the exact structural flaws explicitly staged in the environment, rather than hallucinating faults.",
  'mttr': "Mean Time to Remediate (MTTR) calculates the average absolute clock time consumed by the Sentinel pipeline to process a single file from start to finish. This metric tracks the total lifecycle: initial semantic scanning, prompt generation, LLM inference latency, iterative application side-effects, and the multi-staged validation loop.",
  'tokens': "API Token Efficiency measures the raw underlying cost of the autonomous pipeline. It aggregates the total input prompt context tokens and the output generation tokens consumed per remediation cycle. A lower average indicates a more contextually aware agent that avoids excessive hallucination loops and unnecessary recursive debugging prompts.",
  'mttr_chart': "The Remediation Speed Over Time trajectory tracks the API latency variance and systemic processing delays across sequential test cases. By observing this curve, engineers can identify 'caching' optimizations (where identical payload structures process faster) or degrading inference latency over sustained batch operations.",
  'rigor': "Verification Rigor deconstructs the post-patch testing phase into two competing axes: Adversarial vs. Functional. 'Adversarial Tests' map how many patches strictly defeated the Red Agent's persistent exploitation attempts. 'Functional Tests' track how many of those modified files retained their original expected behaviors (preventing production regressions).",
  'accuracy': "Detection Accuracy splits vulnerability flags into actionable true flaws versus developer noise. 'True Positives' represent mathematically verified, exploitable weaknesses. 'False Positives' are pieces of code structurally misidentified as vulnerable by the scanner that fail to yield a successful real-world exploit payload.",
  'logs': "The Execution Log is a direct architectural matrix charting the pipeline's operational resolution on a per-CVE basis. It maps out sequential pipeline blocks: whether the final patch crashed existing routines (Regression), whether it survived re-injection (Security), and the final orchestration verdict emitted by the validation harness."
};

const PANEL_TITLES = {
  'psr': 'Validation Architecture',
  'tpr': 'Exploit Verification',
  'mttr': 'Latency Overview',
  'tokens': 'Operational Efficiency',
  'mttr_chart': 'Chronological Trajectory Analysis',
  'rigor': 'Validation Subsystem Rigor',
  'accuracy': 'Detection Signal vs Noise',
  'logs': 'Deep Matrix Export'
};

export default function MetricsShowcase() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [hoveredPanel, setHoveredPanel] = useState(null);
  const [activePanel, setActivePanel] = useState(null);

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

  const tpr = summary.total_known_vulns ? ((summary.true_positives / summary.total_known_vulns) * 100).toFixed(1) : 0;
  const psr = summary.true_positives ? ((summary.successful_patches / summary.true_positives) * 100).toFixed(1) : 0;
  const avgMttr = summary.total_cases ? (summary.total_mttr_seconds / summary.total_cases).toFixed(2) : 0;
  const avgTokens = summary.total_cases ? Math.round(summary.total_tokens_used / summary.total_cases) : 0;
  
  const detectionData = [
    { name: 'True Positives', value: summary.true_positives, color: PIE_COLORS.true_positives },
    { name: 'False Positives', value: summary.false_positives, color: PIE_COLORS.false_positives }
  ];

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

  const timelineData = reports.map((report, idx) => ({
    name: `Case ${idx+1}`,
    cve: report.cve,
    mttr: report.mttr_sec,
    patched: report.verification_status === "PASS" ? 1 : 0
  }));

  const panelStyle = (panelId) => {
    if (activePanel) return 'opacity-100';
    const isHovered = hoveredPanel === panelId;
    const isDimmed = hoveredPanel && hoveredPanel !== panelId;
    return `relative transition-all duration-300 cursor-pointer ${isDimmed ? 'opacity-25 blur-[2px] saturate-50' : 'opacity-100'} ${isHovered ? 'z-40 scale-[1.02] shadow-[0_0_30px_rgba(99,102,241,0.15)] ring-1 ring-indigo-500/50' : ''}`;
  };

  const HoverInfo = ({ panelId, align = "right" }) => {
    if (hoveredPanel !== panelId || activePanel) return null;
    return (
      <div className={`absolute top-1/2 -translate-y-1/2 ${align === 'right' ? '-right-72' : '-left-72'} w-64 p-4 bg-slate-900 border border-indigo-500/30 rounded-xl shadow-2xl backdrop-blur-xl z-[100] animate-in fade-in zoom-in duration-200 pointer-events-none`}>
        <div className="flex gap-2 items-start text-indigo-400 mb-1">
          <Info className="w-4 h-4 mt-0.5 shrink-0" />
          <h4 className="text-xs font-bold uppercase tracking-wider">Metric Context</h4>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed font-medium line-clamp-4">
          {PANEL_INFO[panelId]}
        </p>
      </div>
    );
  };

  const renderStatCardInner = (title, value, subtext, Icon, colorClass, isExpanded) => (
    <div className={`flex flex-col h-full bg-[#0f1117] rounded-xl ${isExpanded ? 'justify-center items-center text-center p-12' : 'p-5 border border-white/5'}`}>
      <div className={`flex ${isExpanded ? 'flex-col items-center gap-6 mb-8' : 'justify-between items-start mb-2'} w-full`}>
        <h3 className={`${isExpanded ? 'text-2xl text-slate-300' : 'text-xs text-slate-400'} font-medium uppercase tracking-wider`}>{title}</h3>
        <div className={`rounded-lg ${colorClass} ${isExpanded ? 'p-4' : 'p-1.5'}`}>
          <Icon className={isExpanded ? "w-16 h-16" : "w-4 h-4"} />
        </div>
      </div>
      <div className={`${isExpanded ? 'text-8xl mb-8' : 'text-3xl'} font-bold tracking-tight text-white`}>{value}</div>
      <div className={`${isExpanded ? 'text-xl max-w-sm' : 'text-xs'} text-slate-500 font-mono`}>{subtext}</div>
    </div>
  );

  const RawDataPane = ({ title, colorClass, children }) => (
    <div className={`w-full h-full bg-[#0A0C10] border border-white/5 rounded-2xl flex flex-col overflow-hidden shadow-inner ${colorClass}`}>
       <div className="p-4 bg-white/[0.02] border-b border-white/5 font-semibold uppercase tracking-widest text-sm flex items-center gap-3">
          <ListTree className="w-4 h-4" />
          {title}
       </div>
       <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
          {children}
       </div>
    </div>
  );

  const renderPanelContent = (panelId, isExpanded = false) => {
    switch (panelId) {
      
      // ---------- STAT CARDS ---------- //
      case 'psr':
        return (
          <div className={`w-full h-full flex ${isExpanded ? 'gap-8' : ''}`}>
             <div className={`${isExpanded ? 'w-[60%]' : 'w-full'}`}>
                {renderStatCardInner("Patch Success Rate", `${psr}%`, `${summary.successful_patches} of ${summary.true_positives} vulnerabilities fixed`, ShieldCheck, "bg-emerald-500/20 text-emerald-400", isExpanded)}
             </div>
             {isExpanded && (
                <div className="w-[40%]">
                  <RawDataPane title="Success Breakdown" colorClass="text-emerald-400">
                    <div className="font-mono text-sm space-y-2">
                      {reports.filter(r => r.verification_status === "PASS").map((r,i) => (
                         <div key={i} className="flex flex-col p-3 border border-emerald-500/20 bg-emerald-500/5 rounded-lg">
                           <span className="text-slate-300 font-bold mb-1">{r.cve}</span>
                           <span className="text-emerald-400 text-xs">✓ Security Passed & Functional Active</span>
                         </div>
                      ))}
                      {reports.filter(r => r.verification_status === "PASS").length === 0 && (
                         <div className="text-slate-500 italic p-4 text-center">No successful patches found in this run.</div>
                      )}
                    </div>
                  </RawDataPane>
                </div>
             )}
          </div>
        );
      case 'tpr':
        return (
          <div className={`w-full h-full flex ${isExpanded ? 'gap-8' : ''}`}>
             <div className={`${isExpanded ? 'w-[60%]' : 'w-full'}`}>
               {renderStatCardInner("Recall (TPR)", `${tpr}%`, `${summary.true_positives} of ${summary.total_known_vulns} known flaws found`, Activity, "bg-blue-500/20 text-blue-400", isExpanded)}
             </div>
             {isExpanded && (
                <div className="w-[40%]">
                  <RawDataPane title="Detection Raw Hits" colorClass="text-blue-400">
                    <div className="flex flex-col gap-2 font-mono text-sm">
                      <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                         <div className="text-3xl font-bold text-white">{summary.total_known_vulns}</div>
                         <div className="text-xs text-blue-400 mt-1 uppercase">Total Baseline</div>
                      </div>
                      <div className="p-3 bg-indigo-500/10 border border-indigo-500/20 rounded-lg">
                         <div className="text-3xl font-bold text-white">{summary.true_positives}</div>
                         <div className="text-xs text-indigo-400 mt-1 uppercase">Confirmed Vulnerable</div>
                      </div>
                    </div>
                  </RawDataPane>
                </div>
             )}
          </div>
        );
      case 'mttr':
        return (
          <div className={`w-full h-full flex ${isExpanded ? 'gap-8' : ''}`}>
            <div className={`${isExpanded ? 'w-[60%]' : 'w-full'}`}>
              {renderStatCardInner("Avg MTTR", `${avgMttr}s`, "Mean Time to Remediate per case", Clock, "bg-purple-500/20 text-purple-400", isExpanded)}
            </div>
            {isExpanded && (
                <div className="w-[40%]">
                  <RawDataPane title="Time per operation" colorClass="text-purple-400">
                    <div className="font-mono text-sm space-y-1">
                      {reports.map((r,i) => (
                         <div key={i} className="flex justify-between items-center p-2 border-b border-white/5 last:border-0 hover:bg-white/5">
                           <span className="text-slate-300 text-xs">{r.cve}</span>
                           <span className="text-purple-300 font-bold bg-purple-500/20 px-2 py-0.5 rounded">{r.mttr_sec.toFixed(1)}s</span>
                         </div>
                      ))}
                    </div>
                  </RawDataPane>
                </div>
             )}
          </div>
        );
      case 'tokens':
        return (
          <div className={`w-full h-full flex ${isExpanded ? 'gap-8' : ''}`}>
             <div className={`${isExpanded ? 'w-[60%]' : 'w-full'}`}>
               {renderStatCardInner("Token Efficiency", avgTokens, "LLM tokens used per patch sequence", Zap, "bg-amber-500/20 text-amber-400", isExpanded)}
             </div>
             {isExpanded && (
                <div className="w-[40%]">
                  <RawDataPane title="Aggregate Costs" colorClass="text-amber-400">
                    <div className="flex flex-col h-full justify-center p-6 text-center space-y-8">
                       <div>
                         <div className="text-4xl text-amber-500 font-bold mb-2">{summary.total_tokens_used.toLocaleString()}</div>
                         <div className="text-sm font-mono text-amber-500/70">TOTAL BATCH TOKENS</div>
                       </div>
                       <div>
                         <div className="text-4xl text-yellow-500 font-bold mb-2">~{(summary.total_tokens_used * 0.000003).toFixed(2)}$</div>
                         <div className="text-sm font-mono text-yellow-500/70">ESTIMATED COMPUTE COST</div>
                       </div>
                    </div>
                  </RawDataPane>
                </div>
             )}
          </div>
        );
      
      // ---------- CHARTS ---------- //
      case 'mttr_chart':
        return (
          <div className="w-full h-full flex gap-8">
            <div className={`flex flex-col ${isExpanded ? 'w-[70%]' : 'w-full'} h-full bg-[#0f1117] rounded-xl ${!isExpanded ? 'p-6 py-4' : ''}`}>
              <div className="mb-6 flex-shrink-0">
               <h3 className={`${isExpanded ? 'text-2xl mb-2' : 'text-sm'} font-semibold text-slate-200`}>Remediation Speed Over Time (MTTR)</h3>
               <p className={`${isExpanded ? 'text-base' : 'text-xs'} text-slate-500 mt-1`}>Seconds taken to fully analyze, patch, and verify each case.</p>
              </div>
              <div className={`w-full ${isExpanded ? 'flex-1 min-h-[400px]' : 'h-64'}`}>
               <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData} margin={isExpanded ? { top: 20, right: 30, left: 0, bottom: 0 } : undefined}>
                    <defs>
                      <linearGradient id="colorMttr" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                    <XAxis dataKey="name" stroke="#4b5563" fontSize={isExpanded?14:12} tickLine={false} axisLine={false} />
                    <YAxis stroke="#4b5563" fontSize={isExpanded?14:12} tickLine={false} axisLine={false} />
                    <RechartsTooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px' }} itemStyle={{ color: '#e5e7eb' }} />
                    <Area type="monotone" dataKey="mttr" stroke="#6366f1" strokeWidth={isExpanded?3:2} fillOpacity={1} fill="url(#colorMttr)" name="MTTR (seconds)" />
                  </AreaChart>
               </ResponsiveContainer>
              </div>
            </div>
            
            {isExpanded && (
              <div className="w-[30%]">
                <RawDataPane title="Speed Index Map" colorClass="text-indigo-400">
                  <div className="font-mono text-sm space-y-2">
                    {timelineData.map((d, i) => (
                      <div key={i} className="flex justify-between items-center p-3 border border-indigo-500/10 bg-indigo-500/5 rounded-lg hover:border-indigo-500/30">
                        <span className="text-slate-300 font-bold">{d.cve}</span>
                        <span className="text-indigo-300 tracking-wider bg-[#0f1117] px-2 py-1 rounded">{d.mttr}s</span>
                      </div>
                    ))}
                  </div>
                </RawDataPane>
              </div>
            )}
          </div>
        );

      case 'rigor':
        return (
          <div className="w-full h-full flex gap-8">
            <div className={`flex flex-col ${isExpanded ? 'w-[65%]' : 'w-full'} h-full bg-[#0f1117] rounded-xl ${!isExpanded ? 'p-6 py-4' : ''}`}>
             <div className="mb-4 flex-shrink-0">
               <h3 className={`${isExpanded ? 'text-2xl mb-2' : 'text-sm'} font-semibold text-slate-200`}>Verification Rigor</h3>
               <p className={`${isExpanded ? 'text-base' : 'text-xs'} text-slate-500 mt-1`}>Automated test harness results</p>
             </div>
             <div className={`w-full ${isExpanded ? 'flex-1 min-h-[300px]' : 'flex-1 min-h-[220px]'}`}>
               <ResponsiveContainer width="100%" height="100%">
                 <BarChart data={verificationData} layout="vertical" margin={{ top: 0, right: 30, left: isExpanded?60:30, bottom: 0 }}>
                   <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
                   <XAxis type="number" stroke="#4b5563" fontSize={isExpanded?14:11} />
                   <YAxis dataKey="name" type="category" stroke="#9ca3af" fontSize={isExpanded?16:12} tickLine={false} axisLine={false} width={100} />
                   <RechartsTooltip cursor={{fill: '#1f2937'}} contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px' }}/>
                   <Legend wrapperStyle={{ fontSize: isExpanded?'16px':'12px', marginTop: '10px' }}/>
                   <Bar dataKey="Passed" stackId="a" fill="#10b981" radius={[0, 0, 0, 0]} />
                   <Bar dataKey="Failed" stackId="a" fill="#f43f5e" radius={[0, 4, 4, 0]} />
                 </BarChart>
               </ResponsiveContainer>
             </div>
            </div>

            {isExpanded && (
              <div className="w-[35%]">
                <RawDataPane title="Validation Engine" colorClass="text-emerald-400">
                  <div className="flex flex-col gap-6 p-4">
                    <div className="bg-emerald-500/10 p-5 rounded-xl border border-emerald-500/20 text-center">
                       <TestTube className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                       <div className="text-3xl font-bold text-white mb-1">{summary.adversarial_tests_passed} / {summary.total_adversarial_tests}</div>
                       <div className="text-xs uppercase font-mono text-emerald-500">Adversarial Blocks</div>
                    </div>
                    <div className="bg-emerald-500/10 p-5 rounded-xl border border-emerald-500/20 text-center">
                       <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                       <div className="text-3xl font-bold text-white mb-1">{summary.functional_tests_passed} / {summary.total_functional_tests}</div>
                       <div className="text-xs uppercase font-mono text-emerald-500">Functional Tests Psd</div>
                    </div>
                    <div className="bg-rose-500/10 p-5 rounded-xl border border-rose-500/20 text-center">
                       <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto mb-2 opacity-80" />
                       <div className="text-3xl font-bold text-white mb-1">{summary.regressions_caused}</div>
                       <div className="text-xs uppercase font-mono text-rose-500">Regressions</div>
                    </div>
                  </div>
                </RawDataPane>
              </div>
            )}
          </div>
        );

      case 'accuracy':
        return (
          <div className="w-full h-full flex gap-8">
            <div className={`flex flex-col items-center text-center ${isExpanded ? 'w-[65%]' : 'w-full'} h-full bg-[#0f1117] rounded-xl ${!isExpanded ? 'p-6 py-4' : ''}`}>
              <h3 className={`${isExpanded ? 'text-2xl text-center' : 'text-sm text-left'} font-semibold text-slate-200 w-full`}>Detection Accuracy</h3>
              <p className={`${isExpanded ? 'text-base text-center' : 'text-xs text-left'} text-slate-500 mt-1 w-full mb-4`}>True Positives vs Dev Noise (FPR)</p>
              <div className={`w-full ${isExpanded ? 'flex-1 min-h-[300px]' : 'h-48'}`}>
               <ResponsiveContainer width="100%" height="100%">
                 <PieChart>
                   <Pie data={detectionData} cx="50%" cy="50%" innerRadius={isExpanded?120:60} outerRadius={isExpanded?160:80} paddingAngle={5} dataKey="value" stroke="none">
                     {detectionData.map((entry, index) => ( <Cell key={`cell-${index}`} fill={entry.color} /> ))}
                   </Pie>
                   <RechartsTooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px', padding: '8px' }} itemStyle={{ color: '#e5e7eb', fontSize: '14px' }}/>
                 </PieChart>
               </ResponsiveContainer>
              </div>
              <div className={`w-full flex justify-between px-6 mt-4 ${isExpanded ? 'max-w-xl mx-auto' : ''}`}>
               <div className="text-center">
                 <div className={`${isExpanded ? 'text-5xl' : 'text-2xl'} font-bold text-emerald-400`}>{summary.true_positives}</div>
                 <div className={`${isExpanded ? 'text-sm mt-2' : 'text-[10px]'} text-slate-400 uppercase`}>Exploitable</div>
               </div>
               <div className="text-center">
                 <div className={`${isExpanded ? 'text-5xl' : 'text-2xl'} font-bold text-rose-400`}>{summary.false_positives}</div>
                 <div className={`${isExpanded ? 'text-sm mt-2' : 'text-[10px]'} text-slate-400 uppercase`}>False Flags</div>
               </div>
              </div>
            </div>

            {isExpanded && (
              <div className="w-[35%]">
                <RawDataPane title="Ground Truth Matrix" colorClass="text-emerald-400">
                   <div className="font-mono text-sm flex flex-col gap-3">
                     {reports.map((r, i) => {
                        const isHit = r.verification_status !== "NO_VULNS_FOUND";
                        return (
                          <div key={i} className={`p-4 rounded-xl border flex flex-col gap-2 ${isHit ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-slate-800/50 border-white/5'}`}>
                             <div className="flex justify-between items-center">
                               <span className="text-slate-300 font-bold">{r.cve}</span>
                               {isHit ? (
                                 <span className="bg-emerald-500 text-slate-900 text-[10px] uppercase font-bold px-2 py-0.5 rounded">Detected</span>
                               ) : (
                                 <span className="bg-slate-700 text-slate-300 text-[10px] uppercase font-bold px-2 py-0.5 rounded">Missed</span>
                               )}
                             </div>
                             <div className="text-xs text-slate-400 p-2 bg-[#0A0C10] rounded">{r.ground_truth}</div>
                          </div>
                        );
                     })}
                   </div>
                </RawDataPane>
              </div>
            )}
          </div>
        );

      case 'logs':
        // For logs, it's already a vast list, so we just let it take full width
        return (
          <div className={`w-full flex flex-col h-full bg-[#0f1117] rounded-xl ${!isExpanded ? 'p-6 py-4' : ''}`}>
           <div className={`flex justify-between items-center ${isExpanded ? 'mb-8' : 'mb-6'} flex-shrink-0`}>
             <div>
               <h3 className={`${isExpanded ? 'text-2xl mb-2' : 'text-sm'} font-semibold text-slate-200`}>Execution Log</h3>
               <p className={`${isExpanded ? 'text-base' : 'text-xs'} text-slate-500 mt-1`}>Detailed results of the batch pipeline</p>
             </div>
             <div className={`${isExpanded ? 'text-lg px-4 py-2' : 'text-xs px-2 py-1'} font-mono text-slate-400 bg-white/5 rounded`}>Regressions: <span className={summary.regressions_caused > 0 ? "text-rose-400" : "text-emerald-400"}>{summary.regressions_caused}</span></div>
           </div>
           
           <div className={`w-full overflow-y-auto pr-2 custom-scrollbar ${isExpanded ? 'flex-1' : 'min-h-[224px] pointer-events-none'}`}>
             <table className="w-full text-sm text-left">
               <thead className={`${isExpanded ? 'text-[15px]' : 'text-xs'} text-slate-400 uppercase bg-[#181b24] sticky top-0 backdrop-blur z-10 shadow-sm`}>
                 <tr>
                   <th className="px-6 py-4 font-bold rounded-tl-lg">CVE ID</th>
                   <th className="px-6 py-4 font-bold">Ground Truth</th>
                   <th className="px-6 py-4 font-bold border-l border-white/5 text-center whitespace-nowrap">Regression</th>
                   <th className="px-6 py-4 font-bold text-center text-emerald-500 whitespace-nowrap">Security</th>
                   <th className="px-6 py-4 font-bold text-right rounded-tr-lg">Final Actions</th>
                 </tr>
               </thead>
               <tbody className={isExpanded ? 'text-base' : ''}>
                 {reports.map((report, idx) => (
                   <tr key={idx} className="border-b border-white/5 last:border-0 hover:bg-white/[0.05] transition-colors">
                     <td className="px-6 py-5 font-mono text-slate-300 font-medium">{report.cve}</td>
                     <td className="px-6 py-5 text-slate-400">
                        <span className="inline-block px-3 py-1.5 rounded bg-slate-800/80 text-xs shadow-sm border border-slate-700/50">
                          {report.ground_truth}
                        </span>
                     </td>
                     <td className="px-6 py-5 border-l border-white/5">
                        <div className="flex justify-center">
                          {report.regression_passed === true ? (
                            <div className={`rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)] ${isExpanded ? 'w-4 h-4' : 'w-2 h-2'}`} title="Passed"></div>
                          ) : report.regression_passed === false ? (
                            <div className={`rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.4)] ${isExpanded ? 'w-4 h-4' : 'w-2 h-2'}`} title="Failed"></div>
                          ) : (
                            <div className={`rounded-full bg-slate-600 ${isExpanded ? 'w-4 h-4' : 'w-2 h-2'}`} title="Not Run"></div>
                          )}
                        </div>
                     </td>
                     <td className="px-6 py-5">
                        <div className="flex justify-center">
                          {report.security_passed === true ? (
                            <div className={`rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)] ${isExpanded ? 'w-4 h-4' : 'w-2 h-2'}`} title="Passed"></div>
                          ) : report.security_passed === false ? (
                            <div className={`rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.4)] ${isExpanded ? 'w-4 h-4' : 'w-2 h-2'}`} title="Failed"></div>
                          ) : (
                            <div className={`rounded-full bg-slate-600 ${isExpanded ? 'w-4 h-4' : 'w-2 h-2'}`} title="Not Run"></div>
                          )}
                        </div>
                     </td>
                     <td className="px-6 py-5 text-right">
                       <span className={`${isExpanded ? 'text-sm px-4 py-2 shadow-inner' : 'text-xs px-2 py-1'} rounded font-bold ${report.verification_status === "PASS" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : report.verification_status === "NO_VULNS_FOUND" ? "bg-slate-800 text-slate-400 border border-slate-700" : "bg-rose-500/10 text-rose-400 border border-rose-500/20"}`}>
                         {report.verification_status}
                       </span>
                     </td>
                   </tr>
                 ))}
               </tbody>
             </table>
           </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="space-y-6 pb-24 relative">

      {/* Expanded Active Modal Overlays */}
      {activePanel && (
        <div className="fixed inset-0 z-[200] overflow-hidden flex flex-col pt-36 p-12 items-center animate-in fade-in duration-300">
          <div className="absolute inset-0 bg-slate-950/90 backdrop-blur-xl transition-all cursor-zoom-out" onClick={() => setActivePanel(null)}></div>
          
          {/* Full flex column layout: definition → content → close */}
          <div className="relative z-[210] w-full h-full flex flex-col items-center pointer-events-none">

            {/* Top Full-Width Definition */}
            <div className="w-full pointer-events-none animate-in slide-in-from-top-full duration-500 flex-shrink-0">
               <div className="w-full bg-slate-900/95 border-b border-indigo-500/30 p-8 px-16 shadow-2xl backdrop-blur-xl flex flex-col items-center">
                  <div className="flex items-center gap-3 mb-4 text-indigo-400 bg-indigo-500/10 py-2 px-6 rounded-full border border-indigo-500/20 shadow-inner">
                     <BarChart2 className="w-6 h-6" />
                     <h2 className="text-base font-bold uppercase tracking-widest">{PANEL_TITLES[activePanel]}</h2>
                  </div>
                  <p className="text-[20px] text-slate-200 leading-relaxed max-w-6xl text-center font-medium opacity-90 drop-shadow-sm">
                     {PANEL_INFO[activePanel]}
                  </p>
               </div>
               <p className="text-sm text-slate-500 mt-3 text-center font-mono animate-pulse drop-shadow-md">Click backdrop or button below to close view</p>
            </div>

            {/* Center Expanded Content — fills remaining vertical space */}
            <div className="relative w-full max-w-[90vw] flex-1 min-h-0 bg-[#0f1117] border border-white/5 shadow-[0_0_100px_rgba(0,0,0,0.5)] rounded-[2rem] p-10 my-4 flex items-center scale-100 animate-in zoom-in-95 duration-300 pointer-events-auto overflow-hidden">
              {renderPanelContent(activePanel, true)}
            </div>
            
            {/* Bottom Center Close Button */}
            <button 
              onClick={() => setActivePanel(null)}
              className="flex-shrink-0 mb-4 flex items-center gap-2 bg-slate-800 hover:bg-rose-500/20 text-slate-300 hover:text-rose-400 border border-slate-700 hover:border-rose-500/50 px-6 py-3 rounded-full shadow-2xl backdrop-blur-xl transition-all duration-200 group pointer-events-auto"
            >
               <span className="text-sm uppercase tracking-widest font-bold">Close View</span>
               <X className="w-5 h-5 group-hover:rotate-90 transition-transform duration-300" />
            </button>
          </div>
        </div>
      )}
      
      {/* Top Status Bar */}
      <div className={`flex items-center justify-between p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl transition-opacity duration-300 ${hoveredPanel ? 'opacity-30 blur-[2px]' : ''}`}>
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
        {['psr', 'tpr', 'mttr', 'tokens'].map((id) => (
           <div 
             key={id}
             className={`bg-[#0f1117] border border-white/5 rounded-xl ${panelStyle(id)}`}
             onMouseEnter={() => setHoveredPanel(id)}
             onMouseLeave={() => setHoveredPanel(null)}
             onClick={() => setActivePanel(id)}
           >
             {renderPanelContent(id, false)}
             <HoverInfo panelId={id} align={['psr', 'tpr'].includes(id) ? 'right' : 'left'} />
           </div>
        ))}
      </div>

      {/* Main Charts Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Trajectory Area Chart */}
        <div 
          className={`lg:col-span-2 bg-[#0f1117] border border-white/5 rounded-xl ${panelStyle('mttr_chart')}`}
          onMouseEnter={() => setHoveredPanel('mttr_chart')}
          onMouseLeave={() => setHoveredPanel(null)}
          onClick={() => setActivePanel('mttr_chart')}
        >
           {renderPanelContent('mttr_chart', false)}
           {hoveredPanel === 'mttr_chart' && !activePanel && (
             <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-full mb-6 w-80 p-4 bg-slate-900 border border-indigo-500/30 rounded-xl shadow-2xl backdrop-blur-xl z-[100] animate-in slide-in-from-bottom-2 fade-in duration-200">
               <div className="flex gap-2 items-start text-indigo-400 mb-1">
                 <Info className="w-4 h-4 mt-0.5 shrink-0" />
                 <h4 className="text-xs font-bold uppercase tracking-wider">Metric Context</h4>
               </div>
               <p className="text-sm text-slate-300 leading-relaxed font-medium line-clamp-4">{PANEL_INFO['mttr_chart']}</p>
             </div>
           )}
        </div>

        {/* Verification Rigor Stacked Bar */}
        <div 
          className={`bg-[#0f1117] border border-white/5 rounded-xl ${panelStyle('rigor')}`}
          onMouseEnter={() => setHoveredPanel('rigor')}
          onMouseLeave={() => setHoveredPanel(null)}
          onClick={() => setActivePanel('rigor')}
        >
           {renderPanelContent('rigor', false)}
           <HoverInfo panelId="rigor" align="left" />
        </div>

      </div>

      {/* Bottom Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Detection Accuracy Donut */}
        <div 
          className={`bg-[#0f1117] border border-white/5 rounded-xl ${panelStyle('accuracy')}`}
          onMouseEnter={() => setHoveredPanel('accuracy')}
          onMouseLeave={() => setHoveredPanel(null)}
          onClick={() => setActivePanel('accuracy')}
        >
           {renderPanelContent('accuracy', false)}
           <HoverInfo panelId="accuracy" align="right" />
        </div>

        {/* Detailed List */}
        <div 
          className={`lg:col-span-2 bg-[#0f1117] border border-white/5 rounded-xl ${panelStyle('logs')}`}
          onMouseEnter={() => setHoveredPanel('logs')}
          onMouseLeave={() => setHoveredPanel(null)}
          onClick={() => setActivePanel('logs')}
        >
           {renderPanelContent('logs', false)}
           <HoverInfo panelId="logs" align="left" />
        </div>
      </div>
    </div>
  );
}
