\section{Conclusions and Future Work}

This work presented \textbf{Sentinel}, an autonomous vulnerability remediation framework designed to move beyond passive vulnerability reporting toward a complete \textit{detect $\rightarrow$ patch $\rightarrow$ verify} workflow. By combining a Red Agent for exploit-driven detection, a Blue Agent for LLM-based patch synthesis, and a Green Agent for structural and behavioral verification, the system demonstrates how multiple specialized agents can cooperate to automate a meaningful portion of the software security remediation lifecycle [1, 11, 12, 15].

The experimental results show that the proposed architecture is effective for the supported vulnerability classes. Across the 20-case evaluation benchmark, Sentinel achieved a \textbf{0.00\% false positive rate}, a \textbf{100.00\% conditional patch success rate} on detected cases, a \textbf{0.00\% regression failure rate}, and a \textbf{Mean Time to Remediate of 94.56 seconds}. These results indicate that exploit-grounded security automation can produce not only precise detection, but also trustworthy and behavior-preserving repairs when patch generation is constrained by validation feedback [3, 4, 8, 13, 14].

The project therefore makes several key contributions. First, it demonstrates the value of \textbf{exploit-first vulnerability confirmation}, which reduces false positives by requiring observable failure conditions before remediation begins. Second, it shows that \textbf{LLM-based repair} becomes substantially more reliable when grounded in concrete exploit telemetry rather than generic secure-coding advice. Third, it establishes that \textbf{verification must be a first-class stage} in autonomous remediation systems, since generated patches cannot be trusted unless they successfully block adversarial inputs while preserving legitimate behavior [4, 10, 12].

At the same time, the study also identifies the current boundaries of the system. The main limitation observed in evaluation was the failure to positively detect the four Command Injection benchmark cases, due to the constraints of the present subprocess-based sandbox. In addition, Sentinel currently reasons primarily over single-file targets and stores workflow state in memory, which limits deployment realism and operational durability. These limitations do not weaken the core contribution of the project, but they do clarify that the current system is best understood as a strong proof-of-concept rather than a fully production-ready security platform.

\subsubsection{Future directions can be}

\begin{itemize}
\item \textbf{Stronger sandbox isolation}: Replacing the current local subprocess harness with container-based isolation would allow safer and more realistic execution of operating-system-level exploit classes such as Command Injection.
\item \textbf{Repository-scale reasoning}: Extending the repair process from single-file targets to multi-file codebases would improve applicability to real-world vulnerabilities that span shared modules, routing logic, and framework configuration [12, 14].
\item \textbf{Persistent workflow state}: Integrating durable storage for remediation state and logs would improve reproducibility, auditability, and robustness for longer-running workflows.
\item \textbf{Expanded vulnerability coverage}: Increasing the payload library and benchmark breadth would help Sentinel support a wider range of OWASP-style weaknesses and improve external validity.
\item \textbf{Polyglot language support}: Future versions of the platform could extend beyond Python and target environments such as JavaScript, Java, Go, or PHP.
\item \textbf{Human-in-the-loop governance}: Adding approval gates, explainability summaries, and rollback controls would help align autonomous remediation with practical engineering and organizational requirements.
\end{itemize}

In conclusion, Sentinel shows that autonomous vulnerability remediation is both feasible and promising when it is grounded in empirical exploit evidence and constrained by rigorous post-patch verification. The project demonstrates a practical direction for future work at the intersection of software engineering, cybersecurity, and applied AI, and it provides a strong foundation for more robust, scalable, and trustworthy remediation systems [1, 3, 11, 12, 14].
