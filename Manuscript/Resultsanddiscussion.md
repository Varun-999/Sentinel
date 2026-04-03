\section{Results and Discussion}

\subsection{Description about Dataset}

The results for \textbf{Sentinel} were obtained using a synthetic but executable benchmark generated from a CVE-inspired pipeline. Unlike text-only security datasets, this benchmark contains runnable Python samples that can be attacked, patched, and re-evaluated inside the sandbox environment. This makes the dataset appropriate for measuring the complete \textit{detect $\rightarrow$ patch $\rightarrow$ verify} lifecycle rather than only isolated model performance.

The benchmark contains \textbf{20 test cases}, identified from `CVE-2023-1000` to `CVE-2023-1019`. The cases rotate across five ground-truth vulnerability types:
\begin{itemize}
\item SQL Injection
\item Cross-Site Scripting (XSS)
\item Path Traversal
\item Command Injection
\item Information Exposure
\end{itemize}

Each sample is stored as an executable vulnerable Python file and is processed through the full Sentinel pipeline. During each run, the Red Agent attempts exploit confirmation, the Blue Agent synthesizes a repair, and the Green Agent validates the result through structural and behavioral checks.

\subsection{Detailed Explanation about the Experimental Results}

The experimental findings show that Sentinel is able to move beyond vulnerability reporting and perform measurable autonomous remediation. The most important metrics from the evaluation are summarized below:

\begin{table}[h]
\centering
\caption{Headline Evaluation Metrics of Sentinel}
\begin{tabular}{|l|c|}
\hline
\textbf{Metric} & \textbf{Observed Value} \\
\hline
Total benchmark cases & 20 \\
\hline
Positively detected vulnerable cases & 16 \\
\hline
False positive rate & 0.00\% \\
\hline
Conditional patch success rate & 100.00\% \\
\hline
Regression failure rate & 0.00\% \\
\hline
Mean Time to Remediate (MTTR) & 94.56 seconds \\
\hline
Undetected command injection cases & 4 \\
\hline
\end{tabular}
\label{tab:headline_metrics}
\end{table}

The most significant outcome is the \textbf{0.00\% false positive rate}. This means that every vulnerability flagged by Sentinel corresponded to a reproducible exploit condition inside the sandbox. This is especially important in security automation, where false positives often waste developer time and reduce trust in the system [1, 5, 11].

The second major result is the \textbf{100.00\% conditional patch success rate}. Out of the 16 cases that were positively detected by the Red Agent, every one of them was successfully patched and verified by the downstream Blue and Green agents. This shows that LLM-assisted program repair becomes far more reliable when the repair process is grounded in concrete exploit evidence rather than generic code advice [3, 6, 8, 13, 14].

The system also achieved a \textbf{0.00\% regression failure rate} across patched cases. In other words, every accepted patch not only blocked the exploit payloads that had previously succeeded, but also preserved expected behavior for benign inputs. This is a critical outcome because an automated security system is only useful if it improves security without breaking the target application [4, 10, 12].

From an efficiency perspective, Sentinel recorded a \textbf{Mean Time to Remediate (MTTR) of 94.56 seconds}. This indicates that the complete remediation cycle, including exploit confirmation, patch generation, and verification, can be completed in under two minutes on average for supported cases. Compared with traditional manual workflows, this represents a strong reduction in remediation time [11, 12, 14].

\begin{figure*}
    \centering
    \includegraphics[scale=0.09]{metrics_overview.png}
    \caption{Overall performance metrics of Sentinel across the 20-case benchmark.}
    \label{fig:results_metrics_overview}
\end{figure*}

\subsection{Analysis of Detection and Repair Performance}

The Red Agent demonstrated strong exploit-grounded detection performance for SQL Injection, XSS, Path Traversal, and Information Exposure. In these classes, successful payload execution provided concrete evidence that the target application was truly vulnerable. This exploit-first strategy is one of the major reasons the system achieved zero false positives [1, 7, 11, 15].

The Blue Agent performed effectively when given structured remediation context. Instead of asking the language model for broad security recommendations, Sentinel supplied the vulnerable source code, the confirmed vulnerability label, and the exact successful payloads. This narrowed the search space for repair and helped the generated patches remain directly relevant to the observed exploit condition [3, 4, 8, 9, 13].

The Green Agent's contribution was equally important. Candidate patches were not accepted simply because they looked plausible. Each patch had to survive structural inspection and adversarial replay, followed by benign regression testing. This verification discipline is what turned the patching stage into a trustworthy remediation step rather than a speculative code-generation step [4, 10, 12, 14].

\begin{figure*}
    \centering
    \includegraphics[scale=0.09]{detection_vs_patch_success.png}
    \caption{Comparison of detection count, verified patch count, and remaining undetected cases.}
    \label{fig:detection_vs_patch}
\end{figure*}

\subsection{Discussion of Iterative Behavior}

One of the more useful observations from the experiment is that Sentinel behaves as a closed-loop system rather than a one-shot patch generator. In some runs, the first patch proposed by the Blue Agent did not satisfy the Green Agent. Instead of terminating with a weak result, the system used the verification failure to trigger another repair attempt. This iterative refinement process is important because it acknowledges that LLM outputs are not inherently correct and must be tested before acceptance [4, 13, 14].

This behavior also improves the interpretability of the system. A failed candidate patch is not hidden from the workflow; it becomes part of the remediation evidence chain. As a result, Sentinel behaves more like an experimental security engineer that tests and refines hypotheses than like a static code generator.

\begin{figure*}
    \centering
    \includegraphics[scale=0.09]{iteration_analysis.png}
    \caption{Illustrative iterative refinement behavior showing initial patch failure followed by verified repair.}
    \label{fig:iteration_analysis}
\end{figure*}

\subsection{Limitations and Failure Cases}

Despite the strong overall results, the experiments also exposed an important limitation. The four \textbf{Command Injection} cases in the benchmark were not positively detected. This was not because the vulnerability class is irrelevant, but because the current subprocess-based sandbox could not faithfully reproduce the intended operating-system-level exploit behavior. As a result, these cases remained undetected and therefore unpatched.

This limitation is significant because it shows that the current Sentinel prototype is strongest when the vulnerability can be exercised reliably inside the local harness. For deeper shell-level or environment-sensitive exploit classes, stronger isolation mechanisms such as container-based execution will be necessary to improve realism and coverage.

Another limitation is that the present implementation primarily reasons over a single submitted file. Real-world vulnerabilities often span multiple files, shared modules, configuration layers, and framework boundaries. Extending Sentinel to repository-scale reasoning is therefore an important direction for future work [12, 14].

\begin{figure*}
    \centering
    \includegraphics[scale=0.09]{failure_case_breakdown.png}
    \caption{Failure-case analysis highlighting the command injection detection boundary in the current sandbox setup.}
    \label{fig:failure_case_breakdown}
\end{figure*}

\subsection{Significance of the Proposed Work}

The results demonstrate that Sentinel is not merely a vulnerability scanning tool, but a proof-of-concept autonomous remediation framework. By combining exploit-driven detection, LLM-based patch synthesis, and deterministic post-patch validation, the system shows that a meaningful portion of the security remediation lifecycle can be automated in a measurable and trustworthy way [1, 11, 12, 15].

From a research perspective, the most visually and analytically important findings are the zero false positive rate, the perfect verified patch success rate on detected cases, the zero regression rate, and the sub-two-minute average remediation time. Together, these metrics show that the architecture is both effective and efficient for the supported vulnerability classes.

\begin{table}[h]
\centering
\caption{Interpretation of the Main Experimental Metrics}
\begin{tabular}{|l|p{8cm}|}
\hline
\textbf{Metric} & \textbf{Interpretation} \\
\hline
0.00\% False Positive Rate & Every reported issue was empirically exploitable, improving trust in the detection stage. \\
\hline
100.00\% Conditional Patch Success & Every detected vulnerability received a verified repair, supporting the feasibility of grounded LLM-based remediation. \\
\hline
0.00\% Regression Failure Rate & Accepted patches preserved legitimate functionality while blocking confirmed exploits. \\
\hline
94.56 s MTTR & The full remediation loop completed quickly enough to be practical for interactive security workflows. \\
\hline
4 Undetected Cases & Current limitations are concentrated in command injection under the existing sandbox design. \\
\hline
\end{tabular}
\label{tab:metric_interpretation}
\end{table}

Overall, the Results and Discussion chapter supports the claim that Sentinel can serve as a credible prototype for autonomous vulnerability remediation. The system already demonstrates strong detection precision, reliable repair quality, and rigorous verification, while also clearly revealing the technical boundaries that future versions must overcome.
