import React, { useEffect, useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import RemediationForm from './components/RemediationForm';
import StatusView from './components/StatusView';
import MetricsShowcase from './components/MetricsShowcase';
import VulnerabilityClasses from './components/VulnerabilityClasses';
import { Shield, Activity, Code2, BookOpen } from 'lucide-react';
import { getHealth } from './services/api';

const queryClient = new QueryClient();

function App() {
    const [workflowId, setWorkflowId] = useState(null);
    const [isDevMode, setIsDevMode] = useState(false);
    const [activeTab, setActiveTab] = useState('live');
    const [landingError, setLandingError] = useState('');
    const [serverOnline, setServerOnline] = useState(true);

    const handleReturnHome = (message = '') => {
        setWorkflowId(null);
        setIsDevMode(false);
        setLandingError(message);
    };

    useEffect(() => {
        let cancelled = false;

        const checkHealth = async () => {
            try {
                const data = await getHealth();
                if (!cancelled) {
                    setServerOnline(data?.status === 'online');
                }
            } catch (err) {
                if (!cancelled) {
                    setServerOnline(false);
                }
            }
        };

        checkHealth();
        const intervalId = window.setInterval(checkHealth, 3000);

        return () => {
            cancelled = true;
            window.clearInterval(intervalId);
        };
    }, []);

    return (
        <QueryClientProvider client={queryClient}>
            <div className="min-h-screen text-slate-200 p-8 font-sans selection:bg-indigo-500/30">
                <header className="max-w-screen mx-auto mb-12 flex items-center justify-between border-b border-white/5 pb-6">
                    <div className="flex items-center gap-4">
                        <div className="p-2.5 bg-indigo-500/10 rounded-xl border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.15)]">
                            <Shield className="text-indigo-400 w-8 h-8" />
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                                Sentinel_Code
                                <span className="bg-indigo-500/20 text-indigo-300 text-[10px] px-2 py-0.5 rounded-full border border-indigo-500/30 font-medium">BETA</span>
                            </h1>
                            <p className="text-xs text-slate-400 mt-1 uppercase tracking-widest font-mono">Automated Vulnerability Remediation</p>
                        </div>
                    </div>
                    
                    <div className="flex items-center gap-4">
                        <div className="flex bg-slate-800/50 p-1 rounded-lg border border-white/5">
                           <button 
                             onClick={() => setActiveTab('live')}
                             className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === 'live' ? 'bg-indigo-500/20 text-indigo-300' : 'text-slate-400 hover:text-slate-200'}`}
                           >
                             <Code2 className="w-4 h-4" /> Live Operations
                           </button>
                           <button 
                             onClick={() => setActiveTab('metrics')}
                             className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === 'metrics' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400 hover:text-slate-200'}`}
                           >
                             <Activity className="w-4 h-4" /> Metrics Showcase
                           </button>
                           <button 
                             onClick={() => setActiveTab('vulns')}
                             className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${activeTab === 'vulns' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400 hover:text-slate-200'}`}
                           >
                             <BookOpen className="w-4 h-4" /> Vuln Classes
                           </button>
                        </div>
                        
                        <div
                            className={`inline-flex items-center gap-2 px-3 py-1.5 text-xs rounded-full border backdrop-blur-md font-medium transition-colors ${
                                serverOnline
                                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 shadow-[0_0_10px_rgba(16,185,129,0.1)]'
                                    : 'bg-red-500/10 text-red-400 border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.12)]'
                            }`}
                        >
                            <span className={`w-1.5 h-1.5 rounded-full ${serverOnline ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`}></span>
                            {serverOnline ? 'SYSTEM ONLINE' : 'SERVER OFFLINE'}
                        </div>
                    </div>
                </header>

                <main className="max-w-screen mx-auto space-y-8 relative z-10">
                    {activeTab === 'metrics' ? (
                        <MetricsShowcase />
                    ) : activeTab === 'vulns' ? (
                        <VulnerabilityClasses />
                    ) : (
                        !workflowId ? (
                            <>
                                <RemediationForm
                                    onStart={(id) => {
                                        setLandingError('');
                                        setWorkflowId(id);
                                    }}
                                    initialError={landingError}
                                    onClearInitialError={() => setLandingError('')}
                                />
                                <div className="mt-8 flex justify-center">
                                    <button
                                        onClick={() => { setLandingError(''); setWorkflowId('dev_preview'); setIsDevMode(true); }}
                                        className="text-xs text-slate-500 hover:text-indigo-400 font-mono transition-colors opacity-70 hover:opacity-100 flex items-center gap-1.5 border border-transparent hover:border-indigo-500/30 px-3 py-1.5 rounded-full"
                                    >
                                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
                                        [DEV] Preview Dashboard Layout
                                    </button>
                                </div>
                            </>
                        ) : (
                            <div className="space-y-6">
                                <button
                                    onClick={() => handleReturnHome('')}
                                    className="inline-flex items-center gap-2 text-sm text-indigo-400 hover:text-indigo-300 font-medium transition-colors hover:bg-white/5 px-3 py-1.5 rounded-lg -ml-3"
                                >
                                    ← Return to Mission Control
                                </button>
                                <StatusView
                                    workflowId={workflowId}
                                    isDevMode={isDevMode}
                                    onReturnHome={handleReturnHome}
                                />
                            </div>
                        )
                    )}
                </main>
            </div>
        </QueryClientProvider>
    );
}

export default App;
