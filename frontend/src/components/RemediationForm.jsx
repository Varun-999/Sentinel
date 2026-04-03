import React, { useState, useEffect } from 'react';
import { startRemediation } from '../services/api';
import { Play, Loader2 } from 'lucide-react';

const RemediationForm = ({ onStart, initialError = '', onClearInitialError }) => {
    const [codePath, setCodePath] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    useEffect(() => {
        setError(initialError || '');
    }, [initialError]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        onClearInitialError?.();
        try {
            const data = await startRemediation(codePath);
            onStart(data.workflow_id);
        } catch (err) {
            const errorMessage = err.response?.data?.detail || 'Failed to start remediation. Check console for details.';
            setError(typeof errorMessage === 'string' ? errorMessage : JSON.stringify(errorMessage));
            console.error("Remediation Error:", err);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="bg-[#131A2A]/80 backdrop-blur-xl p-8 rounded-3xl shadow-2xl border border-white/5 relative overflow-hidden group">
            <div className="absolute -top-24 -right-24 w-48 h-48 bg-indigo-500/10 rounded-full blur-3xl opacity-50 group-hover:opacity-75 transition-opacity duration-500 pointer-events-none"></div>
            
            <h2 className="text-xl font-bold mb-6 text-white flex items-center gap-3">
                <div className="p-2 bg-indigo-500/20 rounded-lg text-indigo-400">
                    <Play size={18} className="fill-current" />
                </div>
                Start New Mission
            </h2>
            
            <form onSubmit={handleSubmit} className="space-y-6 relative z-10">
                <div className="space-y-1.5">
                    <label className="block text-sm font-medium text-slate-400">Target File Path</label>
                    <input
                        type="text"
                        value={codePath}
                        onChange={(e) => {
                            setCodePath(e.target.value);
                            if (error) {
                                setError('');
                            }
                            onClearInitialError?.();
                        }}
                        className="block w-full bg-[#0B0F19] border border-white/10 rounded-xl shadow-inner py-3 px-4 text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-all"
                        placeholder="C:/Projects/vulnerable.py"
                        required
                    />
                </div>
                
                {error && (
                    <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm flex items-start gap-2">
                        <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <div>
                            <p>{error}</p>
                            {error.includes('Validation failed:') && (
                                <p className="mt-1 text-red-300/80 text-xs">Update the target path and try again.</p>
                            )}
                        </div>
                    </div>
                )}
                
                <button
                    type="submit"
                    disabled={loading}
                    className="w-full flex justify-center items-center gap-2 py-3.5 px-4 rounded-xl text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[#131A2A] focus:ring-indigo-500 transition-all duration-200 shadow-[0_0_20px_rgba(79,70,229,0.3)] hover:shadow-[0_0_25px_rgba(79,70,229,0.5)] hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none mt-4"
                >
                    {loading ? (
                        <>
                            <Loader2 className="animate-spin w-5 h-5" />
                            <span>Deploying Sentinel...</span>
                        </>
                    ) : (
                        <span>Launch Sequence</span>
                    )}
                </button>
            </form>
        </div>
    );
};

export default RemediationForm;
