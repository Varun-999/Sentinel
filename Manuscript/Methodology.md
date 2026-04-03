\section{Methodology}

The methodology of \textbf{Sentinel} is designed around a live, exploit-grounded remediation workflow rather than a purely diagnostic security scan. Conventional SAST and DAST pipelines are useful for surfacing possible weaknesses, but they often leave the developer with three unresolved tasks: confirming whether the weakness is actually exploitable, constructing a safe fix, and validating that the fix preserves intended behavior [1, 3, 11, 12, 14]. Sentinel addresses this gap through an iterative multi-agent architecture that performs vulnerability detection, patch synthesis, and post-patch verification inside one coordinated system [11, 12, 13].

The methodology consists of a stateful detect-patch-verify cycle. A target Python code artifact is supplied to the system, after which the Red Agent attempts empirical exploitation, the Blue Agent synthesizes a patch using an LLM, and the Green Agent validates the patched result through static and dynamic checks. The overall process is iterative: if verification fails, the workflow loops back to the patch-generation stage until either a valid repair is produced or a configured retry threshold is reached [4, 13, 14].

\protect\\

\subsection{Overall System Architecture}

The Sentinel architecture is organized into four major layers: the frontend monitoring interface, the FastAPI backend, the multi-agent orchestration layer, and the sandboxed execution harness. These components are interconnected through a shared remediation state that captures the current vulnerability status, working payloads, patch attempts, and verification outcomes.

At a high level, the workflow proceeds as follows:
\begin{itemize}
\item A user submits a vulnerable code path through the frontend or a backend request.
\item The backend initializes a remediation workflow and creates a structured state object for that run.
\item The Red Agent executes payloads across supported vulnerability classes and records only successful exploit evidence.
\item The Blue Agent uses the confirmed exploit information and the original source code to generate a candidate patch.
\item The Green Agent validates the patch through syntax-aware checks, adversarial replay, and benign regression testing.
\item If the patch fails validation, the workflow iterates back to the Blue Agent; otherwise, the fix is marked as verified.
\end{itemize}

This architecture reflects the core design principle of Sentinel: security automation should not stop at reporting, but should progress toward an empirically validated remediation outcome [1, 11, 12].

\subsection{Multi-Agent Remediation Pipeline}

\subsubsection{Red Agent: Exploit-Driven Vulnerability Detection}

The Red Agent is responsible for detecting vulnerabilities through active adversarial execution rather than solely through pattern matching. For each submitted target file, it iterates through a predefined library of payloads spanning multiple vulnerability classes, including SQL Injection, Cross-Site Scripting (XSS), Path Traversal, Command Injection, Server-Side Request Forgery (SSRF), Insecure Deserialization, Hardcoded Secrets, Race Conditions, Insecure Randomness, BOLA, XXE, Buffer Overflow patterns, and Information Exposure.

Each payload is delivered to the application while it is running inside the isolated harness. The Red Agent classifies a vulnerability as present only when a payload produces observable evidence of compromise, such as unauthorized data exposure, raw script reflection, filesystem leakage, dangerous command output, or forced error disclosure. Successful payloads are stored as exploit telemetry and later reused during verification [5, 7, 11]. This exploit-grounded methodology reduces false positives and ensures that downstream remediation is based on demonstrated security failures rather than theoretical suspicion.

\subsubsection{Blue Agent: LLM-Based Patch Synthesis}

Once one or more vulnerabilities are confirmed, the Blue Agent constructs a repair prompt using three primary inputs: the original vulnerable code, the list of detected vulnerability classes, and the exact payloads that successfully exploited the target. This prompt is sent to a large language model, which generates a candidate source-code patch intended to neutralize the confirmed attack vectors while preserving legitimate behavior [3, 6, 8, 9, 13, 14].

The Blue Agent is not used as a general conversational assistant. Instead, it operates inside a constrained repair loop in which outputs are expected to be executable code suitable for direct validation. This design follows the broader trend in LLM-based program repair research, where model quality improves when the task is grounded in concrete failure evidence and the objective is explicitly aligned toward correct repair rather than generic explanation [4, 6, 13].

\subsubsection{Green Agent: Structural and Behavioral Verification}

The Green Agent validates the candidate patch before it can be accepted as a successful remediation. Verification occurs in two main stages.

First, the patched code is analyzed structurally to identify whether unsafe constructs associated with the confirmed vulnerability remain present. This static analysis step is intended to catch obvious failures early, such as continued use of unsafe string interpolation, insecure subprocess invocation, or unguarded file-path handling.

Second, the patched application is re-executed inside the sandbox. All payloads that previously succeeded during the Red Agent phase are replayed against the patched version, and benign inputs are also tested to determine whether normal functionality is preserved. A patch is accepted only if the exploit payloads are blocked and the expected non-malicious behavior still succeeds [4, 10, 12, 14]. If either condition fails, the workflow returns to the Blue Agent for another repair attempt.

\subsection{State Management and Workflow Control}

Sentinel uses a stateful orchestration model so that each agent can contribute to the same remediation lifecycle without losing context between phases. The shared state stores the target code path, the list of vulnerability classes to inspect, the vulnerability checklist, the successful payloads, the current patch candidate, verification results, and the iteration count.

This stateful design serves three purposes. First, it allows exploit evidence collected by the Red Agent to be preserved and handed directly to the Blue Agent. Second, it supports iterative repair by letting the Green Agent feed failure information back into the next patch attempt. Third, it enables real-time inspection of the workflow by the frontend dashboard and logging layer. In practice, this state machine is what transforms Sentinel from a collection of isolated tools into a coordinated remediation system [1, 11, 13, 15].

\subsection{Frontend Monitoring Interface}

The frontend of Sentinel is implemented using React, Vite, and TailwindCSS. Its role is not to perform the security analysis itself, but to provide a clear operational interface for launching workflows and observing internal system behavior.

The interface displays live remediation telemetry, including vulnerability status, workflow progress, iteration count, verification status, and generated patch output. It also exposes execution logs so that the operator can inspect which payloads were attempted and how the system responded at each step. This improves transparency and supports developer trust, since the remediation process is visible rather than opaque [10].

\subsection{Backend API and Execution Services}

The backend is implemented using FastAPI and Uvicorn. It serves as the coordination layer between the user interface, the orchestration logic, the LLM service, and the sandbox harness. When a remediation request is received, the backend initializes the workflow, stores the corresponding state, and exposes endpoints for status tracking, patch application, and metrics retrieval.

The backend also manages long-running execution behavior, structured logging, and communication with the LLM provider. Because repair generation may encounter rate limits or provider delays, the backend includes retry handling and controlled failure management to keep the workflow stable during extended runs.

\subsection{Sandboxed Test Harness}

Because Sentinel deliberately executes adversarial payloads, isolation is a critical part of the methodology. The test harness is responsible for launching the target application in a controlled local environment, delivering exploit payloads over HTTP, monitoring the resulting behavior, and tearing the environment down after each test cycle.

In the current implementation, the target vulnerable sample is executed as a subprocess-isolated Flask service bound to localhost. The harness preserves the original file, starts the server, sends vulnerability-specific payloads to the application endpoint, observes the response for success indicators, and restores the original state after execution. This controlled setup allows exploit-driven experimentation without directly exposing the main Sentinel environment to the tested code [11, 12].

\subsection{Dataset and Evaluation Protocol}

The experimental workflow used by Sentinel relies on a synthetic but executable benchmark set generated from a CVE-inspired pipeline. Rather than evaluating on abstract labels alone, the system operates on runnable Python samples that embed concrete vulnerability patterns. This allows each remediation run to be assessed under realistic execution conditions rather than purely textual inspection.

The dataset used in evaluation contains 20 generated test cases spanning five rotating ground-truth vulnerability categories: SQL Injection, XSS, Path Traversal, Command Injection, and Information Exposure. Each case is stored as a sandboxable Python file and enumerated through a manifest for batch processing. During evaluation, Sentinel runs the full remediation pipeline on each case, records phase-level execution traces, and aggregates performance statistics such as detection behavior, verification outcome, and mean time to remediate.

This evaluation methodology is important because it measures Sentinel as an operational system rather than as an isolated model. The objective is not simply to judge whether a model can suggest a plausible patch, but whether the full architecture can detect a vulnerability, produce a repair, and verify that the repair is both secure and behavior-preserving under repeated execution [3, 12, 14].
