from typing import List, Optional
from pydantic import BaseModel, Field

class RemediationState(BaseModel):
    """
    Shared state for the remediation workflow.
    """
    workflow_id: str = Field(..., description="Unique ID for the workflow run.")
    code_path: str = Field(..., description="Path to the vulnerable code file.")
    vulnerability_type: str = Field(..., description="Type of vulnerability (e.g., SQL Injection).")
    
    # Red Agent Outputs
    exploit_success: bool = Field(False, description="Whether the exploit was successful.")
    exploit_payloads: List[str] = Field(default_factory=list, description="List of successful exploit payloads.")
    
    # Blue Agent Outputs
    patch_diff: Optional[str] = Field(None, description="The generated patch in diff format.")
    patch_explanation: Optional[str] = Field(None, description="Explanation of the applied fix.")
    
    # Green Agent Outputs
    verification_status: str = Field("PENDING", description="Verification status: PENDING, PASS, FAIL.")
    verification_reasoning: Optional[str] = Field(None, description="Detailed reasoning from the Green Agent.")
    
    # Workflow Metadata
    iteration_count: int = Field(0, description="Current iteration of the fix-verify loop.")
    max_iterations: int = Field(3, description="Maximum number of retries allowed.")
