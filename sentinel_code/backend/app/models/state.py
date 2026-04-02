from typing import List, Dict, Optional
from pydantic import BaseModel, Field

class RemediationState(BaseModel):
    """
    Shared state for the batch remediation workflow.
    """
    code_path: str = Field(..., description="Path to the vulnerable code file.")
    target_vulnerabilities: List[str] = Field(default_factory=list, description="List of vulnerability types to check.")
    
    # Red Agent Outputs
    vulnerability_checklist: Dict[str, bool] = Field(default_factory=dict, description="Maps vulnerability type to exploit success (True = vulnerable).")
    successful_payloads: Dict[str, List[str]] = Field(default_factory=dict, description="Maps vulnerability type to successful exploit payloads.")
    
    # Blue Agent Outputs
    patch_diff: Optional[str] = Field(None, description="The generated consolidated patch in diff format.")
    patch_explanation: Optional[str] = Field(None, description="Explanation of the applied consolidated fix.")
    
    # Green Agent Outputs
    verification_status: str = Field("PENDING", description="Verification status: PENDING, PASS, FAIL.")
    verification_reasoning: Optional[str] = Field(None, description="Detailed reasoning from the Green Agent.")
    regression_passed: Optional[bool] = Field(None, description="Boolean flag if regression tests passed.")
    security_passed: Optional[bool] = Field(None, description="Boolean flag if security attacks failed after patch.")
    
    # Workflow Metadata
    iteration_count: int = Field(0, description="Current iteration of the fix-verify loop.")
    max_iterations: int = Field(3, description="Maximum number of retries allowed.")
    
    # Identifier for logging/tracking
    workflow_id: Optional[str] = Field(None, description="Unique id assigned when workflow begins.")
