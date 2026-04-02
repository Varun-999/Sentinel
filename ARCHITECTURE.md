# 4. Methodology / Implementation

The core methodology of the Sentinel platform fundamentally breaks away from traditional Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) paradigms. Rather than relying entirely on heuristic pattern-matching or generating theoretical vulnerability reports, the Sentinel methodology proposes a **Live Agentic Remediation Pipeline**. This pipeline autonomously detects security flaws through functional exploitation, synthesizes code-level patches via Large Language Models (LLMs), and mathematically proves the validity of these patches through rigorous adversarial regression testing.

## 4.1. Proposed Algorithm / Model Used

At the center of this methodology is a stateful, iterative multi-agent algorithm that cycles through targeted execution paths. The overall system does not rely on a single ML classifier but utilizes an orchestrated ensemble of algorithmic agents and Large Language Models (LLMs).

1.  **Red Agent (Offensive Algorithm)**: 
    *   *Mechanism*: The Red Agent employs a dynamic payload execution algorithm. When a target user file is provided, the agent systematically iterates through a predefined repository of vulnerability vectors (e.g., SQL Injection, Cross-Site Scripting (XSS), Path Traversal, Command Injection, Insecure Deserialization).
    *   *Execution*: It injects these adversarial payloads against the target application running within a localized sandbox constraint. 
    *   *Output Mapping*: If a payload successfully bypasses the application's native security boundaries (e.g., extracting unauthorized schema data or executing arbitrary OS commands), the algorithm programmatically captures the exact input string that triggered the failure, alongside the corresponding HTTP response. This data continuously updates an accumulated "vulnerability telemetry matrix."

2.  **Blue Agent (Defensive Synthesis Model)**:
    *   *Mechanism*: Unlike traditional engines that point to documentation, the Blue Agent acts as an active patch synthesizer. It consolidates the comprehensive exploit telemetry gathered by the Red Agent into a highly structured context window.
    *   *Prompt Engineering Algorithm*: The algorithm injects the original vulnerable source code, the list of proven vulnerabilities, and the exact failing payloads into a singular, highly engineered Prompt Template. 
    *   *LLM Utilization*: This prompt is fed directly into advanced conversational LLMs (such as OpenAI's GPT-4). The underlying foundational model calculates the necessary syntax required to close all identified vectors simultaneously and generates a unified, optimized code patch. The algorithm constraints the model to ensure it outputs strictly machine-readable code, avoiding extraneous descriptions.

3.  **Green Agent (Verification Algorithm)**:
    *   *Mechanism*: The Green Agent executes a deterministic two-stage validation algorithm to ensure safety before presenting any changes to the end user.
    *   *Stage 1: Static Abstract Syntax Tree (AST) Validation*. The agent parses the newly generated LLM patch into a syntax tree to statically ensure structurally dangerous constructs (such as `shell=True` in subprocess calls or naive string concatenation in SQL parameters) have been decisively removed.
    *   *Stage 2: Dynamic Regression Test*. The agent restarts the sandboxed test server using the *patched* Python code. It then algorithmically fires every previously successful adversarial payload from the Red Agent phase against the new server. 
    *   *Loop Condition*: If the test harness detects that any payload still succeeds, the algorithm registers a failure and loops the execution state back to the Blue Agent for refinement (capped mathematically by a `max_iterations` threshold to prevent infinite loops). If the payloads fail functionally while normal traffic succeeds, the algorithm registers a conclusive "SECURE" state.

## 4.2. Proposed Framework / Tools Used

To support this complex, cyclic workflow while isolating dangerous exploits, Sentinel integrates a modern constellation of performance-oriented frameworks and libraries:

*   **Stateful Orchestration (LangGraph)**: We utilize LangGraph to control the agentic execution flow. It maintains a strictly typed Pydantic state machine (`RemediationState`), tracking variables like `current_vulnerability`, `successful_payloads`, `patched_code`, and `iteration_count` across the node execution boundaries.
*   **Backend Application & Routing (FastAPI & Uvicorn)**: FastAPI forms the robust asynchronous REST layer. Given the long-running execution times of the agentic pipeline, FastAPI leverages Server-Sent Events (SSE) and polling mechanisms to transmit real-time telemetry from the deeply nested Python backend natively to the frontend.
*   **Foundation AI Models (OpenAI API)**: Rather than attempting to train a localized code-generation model from scratch, the architecture relies on OpenAI API frameworks to harness the vast parametric reasoning capabilities of established model versions like GPT-4, utilizing them strictly during the Blue Agent phase.
*   **AST Construction (Tree-Sitter)**: The validation phase relies heavily on `tree-sitter`, a high-performance parsing framework that dynamically compiles structural representations of the synthesized Python code, empowering the Green Agent to implement definitive structural checks that standard regular expressions cannot handle.
*   **Frontend Environment (React, Vite, TailwindCSS)**: The user-facing dashboard is built on React using Vite as the optimized build tool. It translates complex backend state strings into visual telemetry, employing TailwindCSS to render a highly modern, responsive UI interface (featuring dark-mode visuals and animated transition matrices).
*   **Isolation and Containment (Docker)**: Given that the Red Agent actively attempts to run remote code executions (RCE) and logic bypasses on user code, a robust Docker integration is required. The framework dynamically provisions localized Docker containers to run the target code segment separately, providing a bounded execution harness insulated from the core Sentinel platform environment.

## 4.3. Implementation Details (Modules / Components)

The platform architecture is designed natively as an interconnected set of domain-specific modules. This modularity ensures clarity across security contexts, API communications, and user presentation boundaries.

### 4.3.1. Frontend UI (Live Dashboard Module)
This component acts as the operator's mission control system. Its architectural responsibility is strictly limited to data presentation and non-blocking asynchronous state loading.
*   **Telemetry Tracking Panel:** Subscribes to the FastAPI backend state to render critical operation metrics: Total Iterations, Network Integrity, and absolute Verification Status in real time.
*   **Live Vulnerability Matrix:** A dynamically updating left-hand side panel containing a list of standard vulnerabilities (e.g., Injection, SSRF, Deserialization). As the Red Agent systematically assaults the sandbox, the statuses dynamically blink from *Scanning* to either a red *VULNERABLE* flag or a green *SECURE* threshold.
*   **Integrated Operations Log:** A pseudo-terminal viewer that streams raw backend outputs—such as the specific `payload='1 OR 1=1 --'` executions—giving developers deep diagnostic insight into exactly what the agents are testing.
*   **Unified Patch Viewer:** A right-hand side component that renders the final, mathematically proven code implementation, using side-by-side git-style diffs for intuitive developer evaluation.

### 4.3.2. Backend Orchestrator (API Node Module)
The API module acts as the brain stem of the framework, routing all initial operations before transferring execution to the LangGraph node graph.
*   **State Accumulator:** Rather than processing a single vulnerability per request natively, this module enforces a batch accumulation structure. It systematically cascades through all configured vulnerability domains first before triggering validation checks.
*   **Async Event Emitters:** When the API layer triggers the LangGraph process, it simultaneously establishes a detached asynchronous worker, streaming execution state updates to the application disk logs, which are then exposed synchronously for UI consumption.

### 4.3.3. Secure Agentic Pipeline & Sandbox Modules
The most critical tier of Sentinel, strictly encapsulated to prevent unauthorized system access during payload operation.
*   **The Agents Submodule (`red_agent.py`, `blue_agent.py`, `green_agent.py`)**: Individualized Python modules that implement their associated logic flows. Each agent takes in the highly structured `RemediationState` block, modifies fields based on internal conclusions (such as appending working payloads to an array list), and returns the state context for LangGraph to evaluate routing conditions.
*   **The Sandbox Container Module (`test_harness.py`)**: A programmatic wrapper defining the interactions with the localized Docker infrastructure. When analyzing code like a simple vulnerable Flask server script, this module constructs a temporary application space, enforces network boundaries restricting outbound traffic, pushes the payload inputs over isolated HTTP channels, and performs rapid tear-downs the moment analysis cycles finish. 

## 4.4. Dataset Description

Unlike traditional Machine Learning security tools that freeze after being trained on vast repositories of outdated common vulnerabilities and exposures (CVEs), Sentinel is natively a zero-shot, dynamic testing tool. Its architecture prioritizes real-time generation and exploitation over static dataset classification matrices. However, it leverages three distinct data classes during deployment:

1.  **Fundamental LLM Model Weights**: The primary contextual dataset utilized heavily by the Blue Agent is the generalized parametric knowledge embedded within pre-trained Large Language Models (such as GPT-4). This immense pre-trained structure provides unparalleled logic analysis and context derivation without requiring localized retraining loops or database synchronizations.
2.  **Payload Execution Libraries (Deterministic Datasets)**: The Red Agent algorithm operates dynamically but utilizes a predefined mapping of standard adversarial exploit datasets. These lists contain thousands of domain-specific syntax structures ranging from fundamental SQL breakout strings (e.g., `' UNION SELECT NULL, NULL --`) to deep XML External Entity (XXE) and Insecure Deserialization (Pickle/YAML) logic bombs. This deterministic set is constantly expanded manually to introduce novel attack vectors into the pipeline.
3.  **Target Artifacts (Vulnerability Verification Pipelines)**: To maintain the absolute operational integrity of the Sentinel project itself, the platform incorporates a secondary dataset composed of localized code files (e.g., `mega_vulnerable.py`, array injections, bad authorization modules). Rather than serving as data input arrays for the LLMs natively, this repository acts as a regression boundary configuration. It is utilized by the integration testing software to guarantee the red-blue-green pipeline correctly functions against historically dangerous patterns.

The primary operational "Dataset" the application dynamically evaluates per run fundamentally consists solely of the user-provided vulnerable source code. All surrounding metadata and validation logic are derived actively in-memory during platform runtime.
