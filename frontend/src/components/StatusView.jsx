import React, { useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getStatus } from '../services/api';
import { Shield, ShieldAlert, ShieldCheck, Activity, Terminal } from 'lucide-react';

const renderPatchDiff = (patchDiff) => {
    if (!patchDiff) return null;

    const lines = patchDiff.split('\n');

    return lines.map((line, idx) => {
        let lineClass = 'text-slate-300';
        let prefixClass = 'text-slate-600';

        if (line.startsWith('@@')) {
            lineClass = 'text-cyan-300 bg-cyan-500/10';
            prefixClass = 'text-cyan-400';
        } else if (line.startsWith('+')) {
            lineClass = 'text-emerald-300 bg-emerald-500/10';
            prefixClass = 'text-emerald-400';
        } else if (line.startsWith('-')) {
            lineClass = 'text-red-300 bg-red-500/10';
            prefixClass = 'text-red-400';
        }

        const prefix = line.length > 0 ? line[0] : ' ';
        const content = line.length > 0 ? line.slice(1) : '';
        const shouldSplitPrefix = line.startsWith('@@') || line.startsWith('+') || line.startsWith('-');

        return (
            <div
                key={`${idx}-${line}`}
                className={`${lineClass} whitespace-pre font-mono text-[13px] leading-relaxed px-4 ${shouldSplitPrefix ? '' : 'py-[1px]'}`}
            >
                {shouldSplitPrefix ? (
                    <>
                        <span className={`${prefixClass} inline-block w-4 select-none`}>{prefix}</span>
                        <span>{content}</span>
                    </>
                ) : (
                    line || ' '
                )}
            </div>
        );
    });
};

const getPatchFormat = (patchDiff) => {
    if (!patchDiff) return null;

    const lines = patchDiff.split('\n');
    const hasUnifiedHeader = lines.some((line) => line.startsWith('--- ') || line.startsWith('+++ ') || line.startsWith('@@'));
    const hasDiffLines = lines.some((line) => line.startsWith('+') || line.startsWith('-'));

    if (hasUnifiedHeader || hasDiffLines) {
        return 'Unified Diff';
    }

    return 'Full File';
};

const StatusView = ({ workflowId, isDevMode, onReturnHome }) => {
    const { data, error, isLoading } = useQuery({
        queryKey: ['workflow', workflowId],
        queryFn: () => getStatus(workflowId),
        // keep polling only while workflow is in progress
        refetchInterval: (query) => {
            if (isDevMode) return false;
            const currentData = query.state?.data;
            return (currentData && currentData.state && currentData.state.verification_status === 'PENDING') ? 1000 : false;
        },
        enabled: !!workflowId && !isDevMode,
    });
    const [applying, setApplying] = React.useState(false);
    const [applyMsg, setApplyMsg] = React.useState('');
    const logsEndRef = useRef(null);

    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [data?.logs?.events]);

    useEffect(() => {
        if (isDevMode) return undefined;
        const state = data?.state;
        const reason = state?.verification_reasoning || '';
        const isValidationFailure = state?.verification_status === 'FAIL' && reason.startsWith('Validation failed:');

        if (!isValidationFailure) return undefined;

        const redirectTimer = window.setTimeout(() => {
            onReturnHome?.(reason);
        }, 1800);

        return () => window.clearTimeout(redirectTimer);
    }, [data?.state, isDevMode, onReturnHome]);

    const mockData = {
        state: {
            iteration_count: 2,
            max_iterations: 5,
            verification_status: 'PASS',
            verification_reasoning: 'AST Analysis FAILED:\nUnsafe f-string query construction: f"SELECT * FROM {self.table} WHERE {where_clause}"\n\nAutomated Tests PASSED.\nRegression Test (DESERIALIZATION): PASS (Normal input returned data)\nSecurity Test (DESERIALIZATION): PASS (payload failed, effectively patched)',
            target_vulnerabilities: ['SQL', 'XSS', 'PATH_TRAVERSAL', 'DESERIALIZATION', 'COMMAND_INJECTION'],
            patch_diff: '@@ -14,7 +14,7 @@\n def load_user_session(data):\n-    decoded_data = base64.b64decode(session_cookie)\n-    user_obj = pickle.loads(decoded_data)\n+    # VULNERABILITY REMOVED\n+    user_obj = safe_json_load(session_cookie)\n     return getattr(user_obj, "username", "Unknown")',
            vulnerability_checklist: {
                'SQL': false,
                'XSS': true,
                'PATH_TRAVERSAL': false,
                'DESERIALIZATION': true,
                'COMMAND_INJECTION': false
            }
        },
        logs: {
            events: [
                { timestamp: new Date(Date.now() - 50000).toISOString(), agent: 'Orchestrator', action: 'Initialized Batch Remediation Sequence' },
                { timestamp: new Date(Date.now() - 40000).toISOString(), agent: 'Red Agent', action: 'Tested SQL - Secure' },
                { timestamp: new Date(Date.now() - 30000).toISOString(), agent: 'Red Agent', action: 'Tested XSS - VULNERABLE!' },
                { timestamp: new Date(Date.now() - 25000).toISOString(), agent: 'Red Agent', action: 'Tested PATH_TRAVERSAL - Secure' },
                { timestamp: new Date(Date.now() - 20000).toISOString(), agent: 'Red Agent', action: 'Tested DESERIALIZATION - VULNERABLE!' },
                { timestamp: new Date(Date.now() - 15000).toISOString(), agent: 'Blue Agent', action: 'Synthesized consolidated patch for XSS, DESERIALIZATION' },
                { timestamp: new Date(Date.now() - 5000).toISOString(), agent: 'Green Agent', action: 'All verification checks passed' }
            ],
            vulnerability_checklist: {
                'SQL': false,
                'XSS': true,
                'PATH_TRAVERSAL': false,
                'DESERIALIZATION': true,
                'COMMAND_INJECTION': false
            }
        }
    };

    const activeData = isDevMode ? mockData : data;

    if (!isDevMode && isLoading) return <div className="text-center text-green-500 animate-pulse">Establishing uplink...</div>;
    if (!isDevMode && error) return <div className="text-red-500">Connection Lost with Sentinel Operations.</div>;

    const { state, logs } = activeData || {};

    if (!state) return <div className="text-center text-yellow-500">Initializing state...</div>;

    const validationFailure = !isDevMode &&
        state.verification_status === 'FAIL' &&
        typeof state.verification_reasoning === 'string' &&
        state.verification_reasoning.startsWith('Validation failed:');
    const patchFormat = getPatchFormat(state.patch_diff);


    // improved status logic
    let remediationStatus = 'UNKNOWN';
    let statusColor = 'text-yellow-500';

    const checklist = (logs && logs.vulnerability_checklist) ? logs.vulnerability_checklist : (state.vulnerability_checklist || {});
    const anyVulnerable = Object.values(checklist).some(Boolean);

    if (state.verification_status === 'PASS') {
        remediationStatus = 'REMEDIATED';
        statusColor = 'text-green-500'; // Green
    } else if (anyVulnerable) {
        remediationStatus = 'VULNERABLE';
        statusColor = 'text-red-500'; // Red
    } else if (state.verification_status === 'PENDING') {
        remediationStatus = 'ANALYZING';
        statusColor = 'text-yellow-500';
    } else {
        remediationStatus = 'SECURE';
        statusColor = 'text-green-500';
    }

    const getStatusColor = (status) => {
        switch (status) {
            case 'PASS': return 'text-green-500';
            case 'FAIL': return 'text-red-500';
            default: return 'text-yellow-500';
        }
    };

    const handleApply = async () => {
        setApplying(true);
        try {
            // dynamic import to avoid circular dependency if placed in api.js (though it's fine there)
            // assuming applyPatch is exported from api.js
            const { applyPatch } = await import('../services/api');
            await applyPatch(workflowId);
            setApplyMsg('Patch Applied Successfully!');
        } catch (err) {
            console.error(err);
            setApplyMsg('Failed to apply patch.');
        } finally {
            setApplying(false);
        }
    };

    return (
        <div className="space-y-6">
            {validationFailure && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-4 text-red-300 flex items-start gap-3">
                    <ShieldAlert className="w-5 h-5 mt-0.5 shrink-0" />
                    <div>
                        <p className="font-semibold text-red-200">Target validation failed.</p>
                        <p className="text-sm mt-1">{state.verification_reasoning}</p>
                        <p className="text-xs text-red-300/80 mt-2">Returning to Mission Control so you can provide a valid Python target.</p>
                    </div>
                </div>
            )}
            {/* 3-Column Layout: Metrics, Checklist, Live Logs */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 min-h-[500px]">
                {/* Column 1: Metrics */}
                <div className="flex flex-col gap-6">
                    <div className="bg-[#131A2A]/60 backdrop-blur-md p-5 rounded-2xl border border-white/5 shadow-lg relative overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 rounded-full blur-2xl -mr-10 -mt-10 pointer-events-none"></div>
                        <h3 className="text-slate-500 text-xs font-bold uppercase tracking-wider mb-2">Iteration</h3>
                        <div className="flex items-baseline gap-2">
                            <p className="text-3xl font-mono text-white">{state.iteration_count}</p>
                            <p className="text-slate-500 font-mono text-lg">/ {state.max_iterations}</p>
                        </div>
                    </div>

                    <div className="bg-[#131A2A]/60 backdrop-blur-md p-5 rounded-2xl border border-white/5 shadow-lg relative overflow-hidden">
                        <div className={`absolute top-0 right-0 w-32 h-32 rounded-full blur-2xl -mr-10 -mt-10 pointer-events-none ${remediationStatus === 'REMEDIATED' || remediationStatus === 'SECURE' ? 'bg-emerald-500/10' :
                            remediationStatus === 'VULNERABLE' ? 'bg-red-500/10' : 'bg-amber-500/10'
                            }`}></div>
                        <h3 className="text-slate-500 text-xs font-bold uppercase tracking-wider mb-2">Network Status</h3>
                        <p className={`text-2xl font-mono font-bold tracking-tight ${remediationStatus === 'REMEDIATED' || remediationStatus === 'SECURE' ? 'text-emerald-400' :
                            remediationStatus === 'VULNERABLE' ? 'text-red-400' : 'text-amber-400'
                            }`}>
                            {remediationStatus}
                        </p>
                    </div>

                    <div className="bg-[#131A2A]/60 backdrop-blur-md p-5 rounded-2xl border border-white/5 shadow-lg relative overflow-hidden flex-grow">
                        <div className={`absolute top-0 right-0 w-32 h-32 rounded-full blur-2xl -mr-10 -mt-10 pointer-events-none ${state.verification_status === 'PASS' ? 'bg-emerald-500/10' :
                            state.verification_status === 'FAIL' ? 'bg-red-500/10' : 'bg-indigo-500/10'
                            }`}></div>
                        <h3 className="text-slate-500 text-xs font-bold uppercase tracking-wider mb-2">Verification</h3>
                        <p className={`text-2xl font-mono font-bold tracking-tight ${state.verification_status === 'PASS' ? 'text-emerald-400' :
                            state.verification_status === 'FAIL' ? 'text-red-400' : 'text-indigo-400'
                            }`}>
                            {state.verification_status}
                        </p>
                        {/* 
                        <div className="pt-3 border-t border-white/10 font-mono text-[13px] whitespace-pre-wrap leading-relaxed text-slate-400">
                            {state.verification_reasoning || <span className="italic">Waiting for verification analysis...</span>}
                        </div>
                        */}
                    </div>
                </div>
                {/* Left Column: Verification Analysis & Checklist */}
                <div className="bg-[#131A2A]/80 backdrop-blur-md p-5 rounded-2xl border border-white/5 shadow-xl flex flex-col">
                    <div className="flex items-center gap-2 mb-4 pb-3 border-b border-white/5">
                        <div className="p-1.5 bg-amber-500/10 rounded-md text-amber-400">
                            <ShieldCheck size={18} />
                        </div>
                        <h3 className="text-slate-200 font-semibold tracking-wide">Vulnerability Checklist</h3>
                    </div>
                    <div className="bg-[#0B0F19] p-4 rounded-xl text-slate-300 text-sm overflow-y-auto max-h-[400px] flex-grow border border-white/5 shadow-inner">
                        <div className="grid grid-cols-2 gap-3 mb-4">
                            {(state.target_vulnerabilities || []).map(vuln => {
                                const isVuln = checklist[vuln];
                                const isChecked = checklist.hasOwnProperty(vuln);
                                return (
                                    <div key={vuln} className="flex flex-col gap-1 p-2.5 rounded-lg bg-white/[0.03] border border-white/10 hover:bg-white/[0.05] transition-colors h-full justify-center">
                                        <div className="flex justify-between items-center">
                                            <span className="font-mono text-sm font-semibold tracking-wide text-slate-200">{vuln}</span>
                                            {isChecked ? (
                                                isVuln ? <span className="text-red-400 text-[10px] font-black tracking-widest px-2 py-0.5 bg-red-400/10 rounded-full border border-red-400/20">VULNERABLE</span>
                                                    : <span className="text-emerald-400 text-[10px] font-black tracking-widest px-2 py-0.5 bg-emerald-400/10 rounded-full border border-emerald-400/20">SECURE</span>
                                            ) : (
                                                <span className="text-slate-500 text-xs italic animate-pulse">Scanning...</span>
                                            )}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>

                    </div>
                </div>

                {/* Right Column: Live Logs */}
                <div className="bg-[#131A2A]/80 backdrop-blur-md p-5 rounded-2xl border border-white/5 shadow-xl flex flex-col h-full max-h-[500px]">
                    <div className="flex items-center gap-2 mb-4 pb-3 border-b border-white/5">
                        <Terminal size={18} className="text-slate-400" />
                        <h3 className="text-slate-200 font-semibold tracking-wide">Live Operations Log</h3>
                    </div>
                    <div className="overflow-y-auto pr-2 space-y-3 flex-grow font-mono text-[13px]">
                        {logs && logs.events.map((log, idx) => (
                            <div key={idx} className="bg-[#0B0F19] p-3 rounded-xl border border-white/5">
                                <div className="flex items-center gap-3 mb-1.5">
                                    <span className="text-slate-500 text-xs">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                                    <span className={`font-bold px-2 py-0.5 rounded text-xs ${log.agent === 'Orchestrator' ? 'bg-indigo-500/20 text-indigo-300' :
                                        log.agent === 'Red Agent' ? 'bg-red-500/20 text-red-300' :
                                            log.agent === 'Blue Agent' ? 'bg-cyan-500/20 text-cyan-300' :
                                                'bg-emerald-500/20 text-emerald-300'
                                        }`}>{log.agent}</span>
                                    <span className="text-slate-300">{log.action}</span>
                                </div>
                                {log.details && (
                                    <div className="mt-2 pl-3 border-l-2 border-slate-800 overflow-hidden w-full max-w-full">
                                        <pre className="text-slate-400 text-[11px] whitespace-pre-wrap break-words overflow-x-hidden leading-relaxed max-w-full">
                                            {JSON.stringify(log.details, null, 2)}
                                        </pre>
                                    </div>
                                )}
                            </div>
                        ))}
                        {!logs?.events?.length && (
                            <div className="text-slate-500 italic text-center py-8">Awaiting operational telemetry...</div>
                        )}
                        <div ref={logsEndRef} />
                    </div>
                </div>
            </div>

            {/* Bottom: Patch Proposal */}
            <div className="bg-[#131A2A]/80 backdrop-blur-md p-5 rounded-2xl border border-white/5 shadow-xl flex flex-col">
                <div className="flex justify-between items-center mb-4 pb-3 border-b border-white/5">
                    <div className="flex items-center gap-2">
                        <div className="p-1.5 bg-indigo-500/10 rounded-md text-indigo-400">
                            <Activity size={18} />
                        </div>
                        <h3 className="text-slate-200 font-semibold tracking-wide">Proposed Patch</h3>
                        {patchFormat && (
                            <span className={`ml-2 inline-flex items-center rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.18em] ${
                                patchFormat === 'Unified Diff'
                                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                    : 'border-slate-600 bg-slate-800/80 text-slate-300'
                            }`}>
                                {patchFormat}
                            </span>
                        )}
                    </div>
                    {state.patch_diff && state.verification_status === 'PASS' && (
                        <button
                            onClick={handleApply}
                            disabled={applying || applyMsg.includes('Successfully')}
                            className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 font-medium py-1.5 px-4 rounded-lg text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                        >
                            {applying ? 'Deploying...' : (applyMsg || 'Apply Patch')}
                        </button>
                    )}
                </div>

                <div className="bg-[#0B0F19] rounded-xl border border-white/5 overflow-hidden flex-grow flex flex-col shadow-inner">
                    {/* Fake mac window header */}
                    <div className="px-4 py-2 bg-white/[0.02] border-b border-white/5 flex gap-2 items-center">
                        <div className="w-2.5 h-2.5 rounded-full bg-slate-700"></div>
                        <div className="w-2.5 h-2.5 rounded-full bg-slate-700"></div>
                        <div className="w-2.5 h-2.5 rounded-full bg-slate-700"></div>
                        <span className="ml-2 text-xs text-slate-500 font-mono">diff --git</span>
                    </div>
                    <div className="overflow-auto flex-grow max-h-[360px] py-3">
                        {state.patch_diff ? (
                            renderPatchDiff(state.patch_diff)
                        ) : (
                            <div className="px-4 py-1 font-mono text-[13px] leading-relaxed">
                                {state.verification_status === 'PASS' ? (
                                    <span className="text-slate-500">No patch required.</span>
                                ) : (
                                    <span className="text-slate-500 italic">Waiting for patch generation...</span>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default StatusView;
